//! The archive: a local Dolt repo holding every transcript and memory file,
//! one verbatim (redacted) line per row, keyed by (machine, kind, rel_path).
//! A file rebuilt from its rows has the SHA-256 recorded at ingest.
//!
//! Each Mac only ever writes rows with its own `machine`, so syncing
//! archives between Macs merges without conflicts.

use crate::config::Config;
use crate::dolt::{self, get_i64, get_str, Row};
use crate::redact::{self, Counts};
use crate::sources::{self, file_title, KINDS};
use crate::vault::Vault;
use anyhow::{bail, Result};
use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS files (
  machine VARCHAR(64) NOT NULL, kind VARCHAR(16) NOT NULL, rel_path VARCHAR(1024) NOT NULL,
  session_id VARCHAR(36) NOT NULL, title VARCHAR(255) NOT NULL, file_mtime_ms BIGINT NOT NULL,
  line_count INT NOT NULL, sha256 CHAR(64) NOT NULL,
  PRIMARY KEY (machine, kind, rel_path)
);
CREATE TABLE IF NOT EXISTS file_lines (
  machine VARCHAR(64) NOT NULL, kind VARCHAR(16) NOT NULL, rel_path VARCHAR(1024) NOT NULL,
  seq INT NOT NULL, line LONGTEXT NOT NULL,
  PRIMARY KEY (machine, kind, rel_path, seq)
);
CREATE TABLE IF NOT EXISTS syncs (
  machine VARCHAR(64) PRIMARY KEY, synced_at_ms BIGINT NOT NULL, agentd_version VARCHAR(32) NOT NULL
);";

/// Message of the commit that records a sync; it is not an ingest.
pub const SYNC_COMMIT: &str = "record sync";

const IMPORT_BATCH_BYTES: usize = 64 * 1024 * 1024;

/// Paths that may be spliced into SQL. Anything else is filtered in Rust
/// instead (reads) or skips the tail trim (readers ignore rows past
/// line_count, so a skipped trim is wasted space, not wrong data).
pub fn safe_path(p: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9_./-]+$").unwrap())
        .is_match(p)
        && !p.split('/').any(|s| s == "..")
}

pub fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn ready(dir: &Path) -> bool {
    dir.join(".dolt").exists()
}

fn author(machine: &str) -> String {
    format!("agentd <agentd@{machine}>")
}

pub fn ensure(dir: &Path, machine: &str, at_ms: i64) -> Result<()> {
    if !ready(dir) {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let email = format!("agentd@{machine}");
        dolt::dolt(dir, &["init", "--name", "agentd", "--email", &email])?;
        // merge commits from `sync` need a committer identity in this repo
        dolt::dolt(dir, &["config", "--local", "--add", "user.name", "agentd"])?;
        dolt::dolt(dir, &["config", "--local", "--add", "user.email", &email])?;
    }
    dolt::dolt(dir, &["sql", "-q", SCHEMA])?; // IF NOT EXISTS: also repairs a half-finished init
    commit(dir, machine, "create archive schema", at_ms)?;
    Ok(())
}

pub fn dirty(dir: &Path) -> Result<bool> {
    Ok(dolt::count(dir, "SELECT COUNT(*) AS n FROM dolt_status")? > 0)
}

/// Commits are dated when the ingest *started*, so verify can tell a file
/// written mid-ingest ("pending") from one the ingest missed.
pub fn commit(dir: &Path, machine: &str, message: &str, at_ms: i64) -> Result<bool> {
    if !dirty(dir)? {
        return Ok(false);
    }
    dolt::dolt(dir, &["add", "-A"])?;
    dolt::dolt(
        dir,
        &[
            "commit",
            "-m",
            message,
            "--author",
            &author(machine),
            "--date",
            &dolt::iso(at_ms),
        ],
    )?;
    Ok(true)
}

/// Records that this Mac is about to push, so other Macs and the hub can see
/// when each last synced. `machine` is spliced into SQL: dolt:: has no
/// parameters, but config::sanitize_machine limits it to [A-Za-z0-9-].
pub fn record_sync(dir: &Path, machine: &str, at_ms: i64) -> Result<()> {
    // `sync` can run on an archive created before `syncs` existed, and only
    // `ingest` applies SCHEMA; the table is committed together with the row
    dolt::dolt(dir, &["sql", "-q", SCHEMA])?;
    dolt::dolt(
        dir,
        &[
            "sql",
            "-q",
            &format!(
                "REPLACE INTO syncs (machine, synced_at_ms, agentd_version) VALUES ('{machine}', {at_ms}, '{}')",
                env!("CARGO_PKG_VERSION")
            ),
        ],
    )?;
    commit(dir, machine, SYNC_COMMIT, at_ms)?;
    Ok(())
}

/// Start time of this machine's last ingest that changed anything (not the
/// HEAD date: a sync's merge commit or `dolt init` would be "now").
pub fn last_ingest_ms(dir: &Path, machine: &str) -> Result<Option<i64>> {
    let rows = dolt::select(
        dir,
        &format!(
            "SELECT date FROM dolt_log WHERE email = 'agentd@{machine}' AND message <> 'Initialize data repository'
             AND message <> '{SYNC_COMMIT}'
             ORDER BY date DESC LIMIT 1"
        ),
    )?;
    Ok(rows
        .first()
        .and_then(|r| dolt::parse_date_ms(&get_str(r, "date"))))
}

pub struct Entry {
    pub kind: String,
    pub rel_path: String,
    pub session_id: String,
    pub title: String,
    pub mtime_ms: i64,
    pub text: String, // already redacted
    pub trim_tail: bool,
}

pub fn write_entries(
    dir: &Path,
    machine: &str,
    entries: impl IntoIterator<Item = Entry>,
) -> Result<usize> {
    let mut file_rows: Vec<Value> = vec![];
    let mut line_rows: Vec<Value> = vec![];
    let mut line_bytes = 0usize;
    let mut trims: Vec<String> = vec![];
    for e in entries {
        // Split on '\n' keeping every piece, including the empty one after a
        // trailing newline, so join("\n") gives back the exact text.
        let lines: Vec<&str> = e.text.split('\n').collect();
        file_rows.push(json!({
            "machine": machine, "kind": e.kind, "rel_path": e.rel_path, "session_id": e.session_id,
            "title": e.title, "file_mtime_ms": e.mtime_ms, "line_count": lines.len(),
            "sha256": sha256(e.text.as_bytes()),
        }));
        for (seq, line) in lines.iter().enumerate() {
            line_bytes += line.len();
            line_rows.push(json!({ "machine": machine, "kind": e.kind, "rel_path": e.rel_path, "seq": seq, "line": line }));
        }
        if line_bytes > IMPORT_BATCH_BYTES {
            dolt::import(dir, "file_lines", &line_rows)?;
            line_rows.clear();
            line_bytes = 0;
        }
        if e.trim_tail && safe_path(&e.rel_path) {
            trims.push(format!(
                "DELETE FROM file_lines WHERE machine = '{machine}' AND kind = '{}' AND rel_path = '{}' AND seq >= {}",
                e.kind, e.rel_path, lines.len()
            ));
        }
    }
    dolt::import(dir, "file_lines", &line_rows)?;
    // files rows last: a crash mid-ingest leaves old mtimes, so the next run
    // re-reads those files instead of trusting half-written lines.
    dolt::import(dir, "files", &file_rows)?;
    if !trims.is_empty() {
        dolt::dolt(dir, &["sql", "-q", &trims.join(";\n")])?;
    }
    Ok(file_rows.len())
}

#[derive(Serialize, Debug, PartialEq)]
pub struct IngestResult {
    pub ingested: usize,
    pub unchanged: usize,
    pub committed: bool,
    pub redacted: Counts,
}

/// Upsert-only: a file that's gone from disk is never touched, which is the
/// whole point. Only files whose mtime changed since the last ingest are read.
pub fn ingest(cfg: &Config, literals: &[String], vault: Option<&Vault>) -> Result<IngestResult> {
    let dir = cfg.archive_dir();
    let started = dolt::now_ms();
    ensure(&dir, &cfg.machine, started)?;
    let known: HashMap<(String, String), i64> = dolt::select(
        &dir,
        &format!(
            "SELECT kind, rel_path, file_mtime_ms FROM files WHERE machine = '{}'",
            cfg.machine
        ),
    )?
    .iter()
    .map(|r| {
        (
            (get_str(r, "kind"), get_str(r, "rel_path")),
            get_i64(r, "file_mtime_ms"),
        )
    })
    .collect();
    let mut redacted = Counts::new();
    let mut unchanged = 0;
    let mut entries = vec![];
    for kind in KINDS {
        for f in sources::source_files(kind, &cfg.roots) {
            let key = (kind.to_string(), f.rel_path.clone());
            if known.get(&key) == Some(&f.mtime_ms) {
                unchanged += 1;
                continue;
            }
            let Ok(bytes) = std::fs::read(&f.path) else {
                continue;
            };
            let raw = String::from_utf8_lossy(&bytes);
            let (text, counts) = redact::redact_text(&raw, literals, vault)?;
            redact::merge(&mut redacted, &counts);
            entries.push(Entry {
                kind: kind.into(),
                title: file_title(&f, &raw),
                rel_path: f.rel_path,
                session_id: f.session_id,
                mtime_ms: f.mtime_ms,
                text,
                trim_tail: known.contains_key(&key),
            });
        }
    }
    let ingested = write_entries(&dir, &cfg.machine, entries)?;
    let committed = commit(
        &dir,
        &cfg.machine,
        &format!("ingest {ingested} file(s) from {}", cfg.machine),
        started,
    )?;
    Ok(IngestResult {
        ingested,
        unchanged,
        committed,
        redacted,
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct ArchivedFile {
    pub machine: String,
    pub kind: String,
    pub rel_path: String,
    pub session_id: String,
    pub title: String,
    pub mtime_ms: i64,
    pub line_count: i64,
    pub sha256: String,
}

impl ArchivedFile {
    pub fn key(&self) -> String {
        format!("{}\t{}\t{}", self.machine, self.kind, self.rel_path)
    }
}

pub fn archived_files(dir: &Path) -> Result<Vec<ArchivedFile>> {
    if !ready(dir) {
        return Ok(vec![]);
    }
    Ok(dolt::select(
        dir,
        "SELECT machine, kind, rel_path, session_id, title, file_mtime_ms, line_count, sha256 FROM files",
    )?
    .iter()
    .map(|r: &Row| ArchivedFile {
        machine: get_str(r, "machine"),
        kind: get_str(r, "kind"),
        rel_path: get_str(r, "rel_path"),
        session_id: get_str(r, "session_id"),
        title: get_str(r, "title"),
        mtime_ms: get_i64(r, "file_mtime_ms"),
        line_count: get_i64(r, "line_count"),
        sha256: get_str(r, "sha256"),
    })
    .collect())
}

/// Stored text of files matching `where`, keyed by ArchivedFile::key.
/// Rows past a file's line_count (an untrimmed tail) are ignored.
fn rebuild(dir: &Path, where_sql: &str) -> Result<HashMap<String, String>> {
    let rows = dolt::select(
        dir,
        &format!(
            "SELECT l.machine, l.kind, l.rel_path, l.line FROM file_lines l
             JOIN files f ON f.machine = l.machine AND f.kind = l.kind AND f.rel_path = l.rel_path
             WHERE l.seq < f.line_count AND ({where_sql})
             ORDER BY l.machine, l.kind, l.rel_path, l.seq"
        ),
    )?;
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for r in &rows {
        let key = format!(
            "{}\t{}\t{}",
            get_str(r, "machine"),
            get_str(r, "kind"),
            get_str(r, "rel_path")
        );
        out.entry(key).or_default().push(get_str(r, "line"));
    }
    Ok(out.into_iter().map(|(k, v)| (k, v.join("\n"))).collect())
}

fn kind_ok(kind: &str) -> bool {
    KINDS.contains(&kind)
}

/// All stored text for one machine and kind (bounded memory: one group at a time).
pub fn texts_of(dir: &Path, machine: &str, kind: &str) -> Result<HashMap<String, String>> {
    if !kind_ok(kind) || machine != crate::config::sanitize_machine(machine) {
        return Ok(HashMap::new());
    }
    rebuild(
        dir,
        &format!("f.machine = '{machine}' AND f.kind = '{kind}'"),
    )
}

/// Stored text of specific files. Paths reach SQL only if they pass
/// safe_path; otherwise the machine+kind group is read and filtered here.
pub fn texts_for(
    dir: &Path,
    machine: &str,
    kind: &str,
    rels: &[String],
) -> Result<HashMap<String, String>> {
    if rels.is_empty() || !kind_ok(kind) || machine != crate::config::sanitize_machine(machine) {
        return Ok(HashMap::new());
    }
    let want: HashSet<&String> = rels.iter().collect();
    let mut out = HashMap::new();
    let groups: Vec<String> = if rels.iter().all(|p| safe_path(p)) {
        rels.chunks(100)
            .map(|c| {
                let list = c
                    .iter()
                    .map(|p| format!("'{p}'"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("f.machine = '{machine}' AND f.kind = '{kind}' AND f.rel_path IN ({list})")
            })
            .collect()
    } else {
        vec![format!("f.machine = '{machine}' AND f.kind = '{kind}'")]
    };
    for g in groups {
        for (key, text) in rebuild(dir, &g)? {
            let rel = key.splitn(3, '\t').nth(2).unwrap_or_default().to_string();
            if want.contains(&rel) {
                out.insert(rel, text);
            }
        }
    }
    Ok(out)
}

fn machines_and_kinds(files: &[ArchivedFile]) -> Vec<(String, String)> {
    let mut set: Vec<(String, String)> = files
        .iter()
        .map(|f| (f.machine.clone(), f.kind.clone()))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    set.sort();
    set
}

#[derive(Serialize, Debug)]
pub struct RedactResult {
    pub files: usize,
    pub redacted: Counts,
    pub commits_dropped: i64,
}

/// Removes secrets from the archive *and its history*: editing rows in place
/// leaves every earlier Dolt commit holding the old text. Builds a fresh repo
/// holding only the redacted current state (all machines' rows), checks it,
/// swaps it in, and deletes the old repo outright. Remotes are carried over;
/// the next sync force-pushes the new history.
pub fn redact_archive(
    cfg: &Config,
    literals: &[String],
    vault: Option<&Vault>,
) -> Result<RedactResult> {
    let dir = cfg.archive_dir();
    if !ready(&dir) {
        bail!("no archive at {}", dir.display());
    }
    if dirty(&dir)? {
        bail!("archive has uncommitted changes; run `agentd verify` first");
    }
    let last = last_ingest_ms(&dir, &cfg.machine)?.unwrap_or_else(dolt::now_ms);
    let commits_before = dolt::count(&dir, "SELECT COUNT(*) AS n FROM dolt_log")?;
    let remotes = crate::sync::remotes(&dir)?;
    let files = archived_files(&dir)?;

    let fresh = dir.with_extension("rebuild");
    let _ = std::fs::remove_dir_all(&fresh); // only ever a leftover of this function
    ensure(&fresh, &cfg.machine, last)?;
    let mut redacted = Counts::new();
    for (machine, kind) in machines_and_kinds(&files) {
        let texts = texts_of(&dir, &machine, &kind)?;
        let mut entries: Vec<Entry> = vec![];
        for f in files
            .iter()
            .filter(|f| f.machine == machine && f.kind == kind)
        {
            let stored = texts.get(&f.key()).map(String::as_str).unwrap_or("");
            let (text, counts) = redact::redact_text(stored, literals, vault)?;
            redact::merge(&mut redacted, &counts);
            entries.push(Entry {
                kind: f.kind.clone(),
                rel_path: f.rel_path.clone(),
                session_id: f.session_id.clone(),
                title: f.title.clone(),
                mtime_ms: f.mtime_ms,
                text,
                trim_tail: false,
            });
        }
        // each machine's rows keep their machine
        write_entries(&fresh, &machine, entries)?;
    }
    commit(
        &fresh,
        &cfg.machine,
        &format!(
            "snapshot of {} file(s), secrets redacted, history dropped",
            files.len()
        ),
        last,
    )?;

    let check = verify_archive_only(&fresh, literals)?;
    if !check.corrupt.is_empty() || !check.secrets.is_empty() || check.archived != files.len() {
        let _ = std::fs::remove_dir_all(&fresh);
        bail!(
            "rebuilt archive failed its own check (corrupt {}, secrets {}, files {}/{}); old archive left untouched",
            check.corrupt.len(),
            check.secrets.len(),
            check.archived,
            files.len()
        );
    }
    for (name, url) in &remotes {
        dolt::dolt(&fresh, &["remote", "add", name, url])?;
    }
    let old = dir.with_extension("pre-redact");
    std::fs::rename(&dir, &old)?;
    std::fs::rename(&fresh, &dir)?;
    std::fs::remove_dir_all(&old)?; // the Trash would be another copy of the secrets
    if !remotes.is_empty() {
        std::fs::write(cfg.force_push_flag(), "")?;
    }
    let commits_after = dolt::count(&dir, "SELECT COUNT(*) AS n FROM dolt_log")?;
    Ok(RedactResult {
        files: files.len(),
        redacted,
        commits_dropped: commits_before - commits_after,
    })
}

#[derive(Serialize, Debug, Default)]
pub struct Report {
    pub ok: bool,
    pub archive_dir: String,
    pub machine: String,
    pub last_ingest: Option<String>,
    pub clean: bool,
    pub on_disk: usize,
    pub archived: usize,
    pub other_machines: usize,
    /// FAIL: file existed before the last ingest but isn't archived as-is
    pub missed: Vec<String>,
    /// ok: created or changed after the last ingest started
    pub pending: Vec<String>,
    /// FAIL: archive doesn't rebuild the on-disk file (after redaction)
    pub mismatched: Vec<String>,
    /// FAIL: a file doesn't rebuild to the hash and line count recorded at ingest
    pub corrupt: Vec<String>,
    /// FAIL: archived text still contains a secret pattern or saved literal
    pub secrets: Vec<String>,
    /// this Mac's files the agent deleted but the archive kept
    pub archive_only: Vec<String>,
    /// FAIL: the browser's read model is missing or behind the archive
    pub stale_view: Vec<String>,
}

fn verify_archive_only(dir: &Path, literals: &[String]) -> Result<Report> {
    let mut r = Report::default();
    let files = archived_files(dir)?;
    r.archived = files.len();
    for (machine, kind) in machines_and_kinds(&files) {
        let texts = texts_of(dir, &machine, &kind)?;
        for f in files
            .iter()
            .filter(|f| f.machine == machine && f.kind == kind)
        {
            let text = texts.get(&f.key()).map(String::as_str).unwrap_or("");
            if sha256(text.as_bytes()) != f.sha256
                || text.split('\n').count() as i64 != f.line_count
            {
                r.corrupt.push(f.key());
            }
            if redact::total(&redact::find(text, literals)) > 0 {
                r.secrets.push(f.key());
            }
        }
    }
    Ok(r)
}

/// Read-only: checks the archive against itself, this Mac's files on disk,
/// and the browser's read model.
pub fn verify(cfg: &Config, literals: &[String], vault: Option<&Vault>) -> Result<Report> {
    let dir = cfg.archive_dir();
    let mut r = Report {
        archive_dir: dir.display().to_string(),
        machine: cfg.machine.clone(),
        ..Default::default()
    };
    if !ready(&dir) {
        return Ok(r);
    }
    let check = verify_archive_only(&dir, literals)?;
    r.corrupt = check.corrupt;
    r.secrets = check.secrets;
    r.archived = check.archived;
    r.clean = !dirty(&dir)?;
    let last = last_ingest_ms(&dir, &cfg.machine)?;
    r.last_ingest = last.map(dolt::iso);
    let last = last.unwrap_or(0);

    let files = archived_files(&dir)?;
    r.other_machines = files.iter().filter(|f| f.machine != cfg.machine).count();
    let mine: HashMap<(String, String), &ArchivedFile> = files
        .iter()
        .filter(|f| f.machine == cfg.machine)
        .map(|f| ((f.kind.clone(), f.rel_path.clone()), f))
        .collect();
    let mut seen = HashSet::new();
    for kind in KINDS {
        let on_disk = sources::source_files(kind, &cfg.roots);
        let texts = texts_of(&dir, &cfg.machine, kind)?;
        for f in on_disk {
            let key = (kind.to_string(), f.rel_path.clone());
            let label = format!("{kind}:{}", f.rel_path);
            seen.insert(key.clone());
            r.on_disk += 1;
            match mine.get(&key) {
                Some(a) if a.mtime_ms == f.mtime_ms => {
                    let raw = std::fs::read(&f.path).unwrap_or_default();
                    let expected =
                        redact::redact_text(&String::from_utf8_lossy(&raw), literals, vault)?.0;
                    let stored = texts.get(&a.key()).map(String::as_str).unwrap_or("");
                    if sha256(expected.as_bytes()) != sha256(stored.as_bytes()) {
                        r.mismatched.push(label);
                    }
                }
                _ if f.mtime_ms >= last => r.pending.push(label),
                _ => r.missed.push(label),
            }
        }
    }
    r.archive_only = mine
        .keys()
        .filter(|k| !seen.contains(*k))
        .map(|(k, p)| format!("{k}:{p}"))
        .collect();
    r.archive_only.sort();

    let view_shas = crate::view::shas(&cfg.view_db()).unwrap_or_default();
    r.stale_view = files
        .iter()
        .filter(|f| view_shas.get(&f.key()) != Some(&f.sha256))
        .map(ArchivedFile::key)
        .collect();
    r.ok = r.clean
        && r.missed.is_empty()
        && r.mismatched.is_empty()
        && r.corrupt.is_empty()
        && r.secrets.is_empty()
        && r.stale_view.is_empty();
    Ok(r)
}

#[derive(Serialize, Debug, Default)]
pub struct SecretScan {
    pub archive_files: Vec<String>,
    pub archive: Counts,
    pub disk_files: Vec<String>,
    pub disk: Counts,
}

/// What redaction would remove, by kind and file, never the values. The
/// agents' own files are scanned too: agentd never edits them.
pub fn scan_secrets(cfg: &Config, literals: &[String]) -> Result<SecretScan> {
    let dir = cfg.archive_dir();
    let mut s = SecretScan::default();
    if ready(&dir) {
        let files = archived_files(&dir)?;
        for (machine, kind) in machines_and_kinds(&files) {
            for (key, text) in texts_of(&dir, &machine, &kind)? {
                let c = redact::find(&text, literals);
                if redact::total(&c) > 0 {
                    s.archive_files.push(key);
                    redact::merge(&mut s.archive, &c);
                }
            }
        }
    }
    for kind in KINDS {
        for f in sources::source_files(kind, &cfg.roots) {
            let Ok(raw) = std::fs::read(&f.path) else {
                continue;
            };
            let c = redact::find(&String::from_utf8_lossy(&raw), literals);
            if redact::total(&c) > 0 {
                s.disk_files.push(format!("{kind}:{}", f.rel_path));
                redact::merge(&mut s.disk, &c);
            }
        }
    }
    Ok(s)
}
