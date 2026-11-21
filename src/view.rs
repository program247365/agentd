//! The browser's read model: a SQLite file derived from the Dolt archive,
//! holding per-file metadata and every event, full-text indexed. Dolt stays
//! the source of truth; this exists so listing, paging and searching never
//! spawn a dolt process per request. `search` reads it too (sessions +
//! events) to index sessions deleted here or recorded on other Macs.

use crate::archive::{self, ArchivedFile};
use crate::config::Config;
use crate::sources::{self, is_memory};
use crate::transcript;
use anyhow::Result;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  machine TEXT NOT NULL, kind TEXT NOT NULL, rel_path TEXT NOT NULL, session_id TEXT NOT NULL,
  sha256 TEXT NOT NULL, title TEXT NOT NULL, cwd TEXT NOT NULL, models TEXT NOT NULL,
  started_at TEXT NOT NULL, ended_at TEXT NOT NULL, messages INTEGER NOT NULL,
  tool_calls INTEGER NOT NULL, first_prompt TEXT NOT NULL, events INTEGER NOT NULL, mtime_ms INTEGER NOT NULL,
  PRIMARY KEY (machine, kind, rel_path)
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, machine TEXT NOT NULL, kind TEXT NOT NULL, rel_path TEXT NOT NULL,
  idx INTEGER NOT NULL, seq INTEGER NOT NULL, ts TEXT NOT NULL, role TEXT NOT NULL,
  model TEXT, name TEXT, text TEXT NOT NULL, error INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_file ON events (machine, kind, rel_path, idx);
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
  text, content='events', content_rowid='id', tokenize='porter unicode61'
);
CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
  INSERT INTO events_fts (rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
  INSERT INTO events_fts (events_fts, rowid, text) VALUES ('delete', old.id, old.text);
END;";

fn open_rw(db: &Path) -> Result<Connection> {
    if let Some(dir) = db.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let conn = Connection::open(db)?;
    conn.execute_batch(SCHEMA)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(db, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(conn)
}

fn open_ro(db: &Path) -> Result<Option<Connection>> {
    if !db.exists() {
        return Ok(None);
    }
    Ok(Some(Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?))
}

/// sha256 per archived file, keyed like ArchivedFile::key; for verify.
pub fn shas(db: &Path) -> Result<HashMap<String, String>> {
    let Some(conn) = open_ro(db)? else {
        return Ok(HashMap::new());
    };
    let mut stmt = conn.prepare("SELECT machine, kind, rel_path, sha256 FROM sessions")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            format!(
                "{}\t{}\t{}",
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?
            ),
            r.get(3)?,
        ))
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Update {
    pub refreshed: usize,
    pub removed: usize,
    pub total: usize,
}

/// Brings the view in line with the archive: files whose stored sha256
/// changed are re-parsed; files no longer archived are dropped. Only the
/// (machine, kind) groups with changes are read out of Dolt.
pub fn update(cfg: &Config, db: &Path) -> Result<Update> {
    let dir = cfg.archive_dir();
    let files = archive::archived_files(&dir)?;
    let mut conn = open_rw(db)?;
    let have = shas(db)?;
    let stale: Vec<&ArchivedFile> = files
        .iter()
        .filter(|f| have.get(&f.key()) != Some(&f.sha256))
        .collect();
    let keep: std::collections::HashSet<String> = files.iter().map(ArchivedFile::key).collect();
    let gone: Vec<String> = have
        .keys()
        .filter(|k| !keep.contains(*k))
        .cloned()
        .collect();

    let tx = conn.transaction()?;
    for key in &gone {
        let p: Vec<&str> = key.splitn(3, '\t').collect();
        tx.execute(
            "DELETE FROM events WHERE machine = ?1 AND kind = ?2 AND rel_path = ?3",
            params![p[0], p[1], p[2]],
        )?;
        tx.execute(
            "DELETE FROM sessions WHERE machine = ?1 AND kind = ?2 AND rel_path = ?3",
            params![p[0], p[1], p[2]],
        )?;
    }
    tx.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('machine', ?1)",
        params![cfg.machine],
    )?;
    tx.commit()?;

    let mut groups: BTreeMap<(String, String), Vec<&ArchivedFile>> = BTreeMap::new();
    for f in &stale {
        groups
            .entry((f.machine.clone(), f.kind.clone()))
            .or_default()
            .push(f);
    }
    for ((machine, kind), group) in groups {
        let rels: Vec<String> = group.iter().map(|f| f.rel_path.clone()).collect();
        let texts = archive::texts_for(&dir, &machine, &kind, &rels)?;
        let tx = conn.transaction()?;
        for f in group {
            let text = texts.get(&f.rel_path).map(String::as_str).unwrap_or("");
            let (events, meta) = if is_memory(&f.kind) {
                transcript::parse_memory(text, &f.title)
            } else {
                transcript::parse(text)
            };
            tx.execute(
                "DELETE FROM events WHERE machine = ?1 AND kind = ?2 AND rel_path = ?3",
                params![f.machine, f.kind, f.rel_path],
            )?;
            tx.execute(
                "INSERT OR REPLACE INTO sessions (machine, kind, rel_path, session_id, sha256, title, cwd, models,
                   started_at, ended_at, messages, tool_calls, first_prompt, events, mtime_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    f.machine,
                    f.kind,
                    f.rel_path,
                    f.session_id,
                    f.sha256,
                    meta.title.clone().unwrap_or_else(|| f.title.clone()),
                    meta.cwd.clone().unwrap_or_default(),
                    meta.models.join("\n"),
                    meta.started_at,
                    meta.ended_at,
                    meta.messages as i64,
                    meta.tool_calls as i64,
                    meta.first_prompt,
                    events.len() as i64,
                    f.mtime_ms,
                ],
            )?;
            {
                let mut ins = tx.prepare_cached(
                    "INSERT INTO events (machine, kind, rel_path, idx, seq, ts, role, model, name, text, error)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                )?;
                for (idx, e) in events.iter().enumerate() {
                    ins.execute(params![
                        f.machine,
                        f.kind,
                        f.rel_path,
                        idx as i64,
                        e.seq as i64,
                        e.ts,
                        e.role,
                        e.model,
                        e.name,
                        e.text,
                        e.error as i64
                    ])?;
                }
            }
        }
        tx.commit()?;
    }
    Ok(Update {
        refreshed: stale.len(),
        removed: gone.len(),
        total: files.len(),
    })
}

/// Rebuild from nothing (after a redact, so no pre-redaction text survives in
/// the file's free pages). Atomic rename, like the archive swap.
pub fn rebuild(cfg: &Config, db: &Path) -> Result<Update> {
    let tmp = db.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let r = update(cfg, &tmp)?;
    for side in ["sqlite-wal", "sqlite-shm"] {
        let _ = std::fs::remove_file(db.with_extension(side));
    }
    std::fs::rename(&tmp, db)?;
    Ok(r)
}

// ── queries ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone)]
pub struct SessionRow {
    pub machine: String,
    pub kind: String,
    pub rel_path: String,
    pub session_id: String,
    /// session, subagent or memory
    pub shape: String,
    pub title: String,
    pub cwd: String,
    pub models: Vec<String>,
    pub started_at: String,
    pub ended_at: String,
    pub messages: i64,
    pub tool_calls: i64,
    pub first_prompt: String,
    pub events: i64,
    /// last activity: the transcript's end, else the file's mtime (memory)
    pub updated_at: String,
    /// this Mac's file is still on disk; always false for other Macs' files
    pub on_disk: bool,
    pub this_machine: bool,
    pub hits: Option<i64>,
    pub snippet: Option<String>,
    pub hit_idx: Option<i64>,
}

#[derive(Debug, Default, Clone)]
pub struct Query {
    pub kind: Option<String>, // claude, codex, pi, memory
    pub model: Option<String>,
    pub machine: Option<String>,
    pub q: Option<String>,
    pub subagents: bool,
    pub deleted_only: bool,
    pub page: usize,
    pub limit: usize,
}

#[derive(Debug, Serialize)]
pub struct Page {
    pub total: usize,
    pub page: usize,
    pub pages: usize,
    pub machine: String,
    pub sessions: Vec<SessionRow>,
    pub facets: Facets,
}

#[derive(Debug, Serialize, Default)]
pub struct Facets {
    pub kinds: BTreeMap<String, usize>,
    pub models: BTreeMap<String, usize>,
    pub machines: BTreeMap<String, usize>,
}

/// FTS match marks are control characters so the client escapes the text
/// first and only then turns them into <mark>.
pub const MARK_OPEN: &str = "\u{1}";
pub const MARK_CLOSE: &str = "\u{2}";

/// Lenient OR of the query's words, each quoted (FTS5 errors on bare punctuation).
pub fn match_query(q: &str) -> Option<String> {
    let words: Vec<String> = q
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| format!("\"{w}\""))
        .collect();
    (!words.is_empty()).then(|| words.join(" OR "))
}

fn row_from(r: &rusqlite::Row, cfg: &Config) -> rusqlite::Result<SessionRow> {
    let machine: String = r.get("machine")?;
    let kind: String = r.get("kind")?;
    let rel_path: String = r.get("rel_path")?;
    let session_id: String = r.get("session_id")?;
    let models: String = r.get("models")?;
    let ended_at: String = r.get("ended_at")?;
    let mtime_ms: i64 = r.get("mtime_ms")?;
    let this_machine = machine == cfg.machine;
    let on_disk = this_machine
        && sources::kind_root(&kind, &cfg.roots)
            .join(&rel_path)
            .exists();
    Ok(SessionRow {
        shape: if is_memory(&kind) {
            "memory".into()
        } else if session_id.is_empty() {
            "subagent".into()
        } else {
            "session".into()
        },
        title: r.get("title")?,
        cwd: r.get("cwd")?,
        models: if models.is_empty() {
            vec![]
        } else {
            models.split('\n').map(str::to_string).collect()
        },
        started_at: r.get("started_at")?,
        updated_at: if ended_at.is_empty() {
            crate::dolt::iso(mtime_ms)
        } else {
            ended_at.clone()
        },
        ended_at,
        messages: r.get("messages")?,
        tool_calls: r.get("tool_calls")?,
        first_prompt: r.get("first_prompt")?,
        events: r.get("events")?,
        on_disk,
        this_machine,
        hits: None,
        snippet: None,
        hit_idx: None,
        machine,
        kind,
        rel_path,
        session_id,
    })
}

pub fn list(cfg: &Config, db: &Path, q: &Query) -> Result<Page> {
    let limit = q.limit.clamp(1, 200);
    let page = q.page.max(1);
    let mut out = Page {
        total: 0,
        page,
        pages: 0,
        machine: cfg.machine.clone(),
        sessions: vec![],
        facets: Facets::default(),
    };
    let Some(conn) = open_ro(db)? else {
        return Ok(out);
    };
    let mut stmt = conn.prepare("SELECT * FROM sessions")?;
    let mut rows: Vec<SessionRow> = stmt
        .query_map([], |r| row_from(r, cfg))?
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|r| match q.kind.as_deref() {
            None | Some("") => true,
            Some("memory") => r.shape == "memory",
            Some(k) => r.kind == k,
        })
        .filter(|r| {
            q.model
                .as_deref()
                .map_or(true, |m| m.is_empty() || r.models.iter().any(|x| x == m))
        })
        .filter(|r| {
            q.machine
                .as_deref()
                .map_or(true, |m| m.is_empty() || r.machine == m)
        })
        .filter(|r| q.subagents || r.shape != "subagent")
        .filter(|r| !q.deleted_only || (r.this_machine && !r.on_disk))
        .collect();
    // newest activity first; both kinds of timestamp are UTC RFC 3339
    rows.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

    if let Some(text) = q.q.as_deref().filter(|t| !t.trim().is_empty()) {
        let Some(m) = match_query(text) else {
            return Ok(out);
        };
        // Every matching event, best first; the first per file gives its
        // rank, snippet and the event the UI jumps to.
        let mut best: HashMap<String, (i64, usize, i64, String)> = HashMap::new();
        let mut stmt = conn.prepare(&format!(
            "SELECT e.machine, e.kind, e.rel_path, e.idx,
                    snippet(events_fts, 0, '{MARK_OPEN}', '{MARK_CLOSE}', '…', 24)
             FROM events_fts JOIN events e ON e.id = events_fts.rowid
             WHERE events_fts MATCH ?1 ORDER BY bm25(events_fts) LIMIT 20000"
        ))?;
        let hits = stmt.query_map(params![m], |r| {
            Ok((
                format!(
                    "{}\t{}\t{}",
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?
                ),
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        for (rank, h) in hits.enumerate() {
            let (key, idx, snippet) = h?;
            best.entry(key)
                .and_modify(|b| b.0 += 1)
                .or_insert((1, rank, idx, snippet));
        }
        rows.retain(|r| best.contains_key(&format!("{}\t{}\t{}", r.machine, r.kind, r.rel_path)));
        for r in rows.iter_mut() {
            let b = &best[&format!("{}\t{}\t{}", r.machine, r.kind, r.rel_path)];
            r.hits = Some(b.0);
            r.hit_idx = Some(b.2);
            r.snippet = Some(b.3.clone());
        }
        rows.sort_by_key(|r| best[&format!("{}\t{}\t{}", r.machine, r.kind, r.rel_path)].1);
    }
    for r in &rows {
        *out.facets
            .kinds
            .entry(if r.shape == "memory" {
                "memory".into()
            } else {
                r.kind.clone()
            })
            .or_default() += 1;
        *out.facets.machines.entry(r.machine.clone()).or_default() += 1;
        for m in &r.models {
            *out.facets.models.entry(m.clone()).or_default() += 1;
        }
    }
    out.total = rows.len();
    out.pages = rows.len().div_ceil(limit);
    out.sessions = rows
        .into_iter()
        .skip((page - 1) * limit)
        .take(limit)
        .collect();
    Ok(out)
}

#[derive(Debug, Serialize)]
pub struct EventRow {
    pub idx: i64,
    pub seq: i64,
    pub ts: String,
    pub role: String,
    pub model: Option<String>,
    pub name: Option<String>,
    pub text: String,
    pub error: bool,
}

#[derive(Debug, Serialize)]
pub struct SessionPage {
    pub session: SessionRow,
    pub events: Vec<EventRow>,
    pub offset: i64,
}

pub fn get(
    cfg: &Config,
    db: &Path,
    machine: &str,
    kind: &str,
    rel: &str,
    offset: i64,
    limit: i64,
) -> Result<Option<SessionPage>> {
    let Some(conn) = open_ro(db)? else {
        return Ok(None);
    };
    let session = conn
        .query_row(
            "SELECT * FROM sessions WHERE machine = ?1 AND kind = ?2 AND rel_path = ?3",
            params![machine, kind, rel],
            |r| row_from(r, cfg),
        )
        .optional()?;
    let Some(session) = session else {
        return Ok(None);
    };
    let offset = offset.max(0);
    let mut stmt = conn.prepare(
        "SELECT idx, seq, ts, role, model, name, text, error FROM events
         WHERE machine = ?1 AND kind = ?2 AND rel_path = ?3 AND idx >= ?4 ORDER BY idx LIMIT ?5",
    )?;
    let events = stmt
        .query_map(
            params![machine, kind, rel, offset, limit.clamp(1, 1000)],
            |r| {
                Ok(EventRow {
                    idx: r.get(0)?,
                    seq: r.get(1)?,
                    ts: r.get(2)?,
                    role: r.get(3)?,
                    model: r.get(4)?,
                    name: r.get(5)?,
                    text: r.get(6)?,
                    error: r.get::<_, i64>(7)? == 1,
                })
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(Some(SessionPage {
        session,
        events,
        offset,
    }))
}
