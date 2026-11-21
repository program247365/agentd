//! Finding the files to archive: agent transcripts and agent memory.

use crate::config::Roots;
use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use walkdir::WalkDir;

/// What a file is. Stored in the archive's `kind` column.
pub const KINDS: [&str; 5] = ["claude", "codex", "pi", "claude-memory", "codex-memory"];

pub fn is_memory(kind: &str) -> bool {
    kind.ends_with("-memory")
}

#[derive(Clone, Debug)]
pub struct SourceFile {
    pub kind: &'static str,
    /// Path relative to the kind's root, '/'-separated.
    pub rel_path: String,
    /// The session UUID for top-level transcripts; empty for subagent
    /// transcripts and memory files.
    pub session_id: String,
    pub path: PathBuf,
    /// Floored to whole milliseconds: stored as BIGINT and compared for
    /// equality, so a fractional mtime would re-ingest forever.
    pub mtime_ms: i64,
}

fn session_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.jsonl$")
            .unwrap()
    })
}

/// The directory a kind's rel_paths are relative to.
pub fn kind_root(kind: &str, roots: &Roots) -> PathBuf {
    match kind {
        "claude" | "claude-memory" => roots.claude_projects.clone(),
        "codex" => roots.codex_sessions.clone(),
        "codex-memory" => roots.codex_home.clone(),
        _ => roots.pi_sessions.clone(),
    }
}

fn mtime_ms(path: &Path) -> Option<i64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let d = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(d.as_millis() as i64)
}

fn walk(root: &Path, keep: impl Fn(&str) -> bool) -> Vec<(String, PathBuf)> {
    if !root.exists() {
        return vec![];
    }
    let mut out: Vec<(String, PathBuf)> = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| {
            let rel = e
                .path()
                .strip_prefix(root)
                .ok()?
                .to_str()?
                .replace('\\', "/");
            keep(&rel).then(|| (rel, e.path().to_path_buf()))
        })
        .collect();
    out.sort();
    out
}

pub fn source_files(kind: &'static str, roots: &Roots) -> Vec<SourceFile> {
    let root = kind_root(kind, roots);
    let found = match kind {
        "claude" | "codex" | "pi" => walk(&root, |rel| rel.ends_with(".jsonl")),
        // <project>/memory/**/*.md
        "claude-memory" => walk(&root, |rel| {
            rel.ends_with(".md") && rel.split('/').nth(1) == Some("memory")
        }),
        // memories/**/*.md or memories_v2/**/*.md under ~/.codex
        "codex-memory" => walk(&root, |rel| {
            rel.ends_with(".md")
                && matches!(rel.split('/').next(), Some("memories" | "memories_v2"))
        }),
        _ => vec![],
    };
    found
        .into_iter()
        .filter_map(|(rel_path, path)| {
            let session_id = if is_memory(kind) {
                String::new()
            } else {
                session_re()
                    .captures(&rel_path)
                    .map(|c| c[1].to_string())
                    .unwrap_or_default()
            };
            Some(SourceFile {
                kind,
                mtime_ms: mtime_ms(&path)?,
                rel_path,
                session_id,
                path,
            })
        })
        .collect()
}

/// A readable title: Claude's cwd basename for transcripts (read from the
/// first 4 KB), a memory file's frontmatter `name:`, else the file name.
pub fn file_title(f: &SourceFile, text: &str) -> String {
    let head: String = text.chars().take(4096).collect();
    let title = if is_memory(f.kind) {
        Regex::new(r"(?m)^name:\s*(.+)$")
            .unwrap()
            .captures(head.strip_prefix("---\n").unwrap_or(""))
            .map(|c| c[1].trim().to_string())
    } else {
        Regex::new(r#""cwd":"([^"]+)""#)
            .unwrap()
            .captures(&head)
            .and_then(|c| c[1].rsplit('/').next().map(str::to_string))
    };
    title
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| {
            f.rel_path
                .rsplit('/')
                .next()
                .unwrap_or(&f.rel_path)
                .to_string()
        })
        .chars()
        .take(255)
        .collect()
}
