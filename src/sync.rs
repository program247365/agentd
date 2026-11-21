//! Syncing archives between Macs through any Dolt remote (`dolt remotesrv`
//! on a home server over Tailscale, an S3/R2 bucket, a NAS folder, DoltHub).
//! A fresh install has no remote and stays local-only.
//!
//! Merges can't conflict: every row is keyed by the machine that wrote it.
//! History rewrites (a redact on any Mac) propagate: the redacting Mac
//! force-pushes, and every other Mac, finding no common ancestor, resets to
//! the remote and re-adds its own files from disk and from what it held.

use crate::archive::{self, Entry};
use crate::config::Config;
use crate::dolt::{self, get_str};
use crate::redact;
use crate::sources::{self, KINDS};
use crate::vault::Vault;
use anyhow::{bail, Result};
use serde::Serialize;
use std::path::Path;

const REMOTE: &str = "origin";
const BRANCH: &str = "main";

pub fn remotes(dir: &Path) -> Result<Vec<(String, String)>> {
    if !archive::ready(dir) {
        return Ok(vec![]);
    }
    Ok(dolt::select(dir, "SELECT name, url FROM dolt_remotes")?
        .iter()
        .map(|r| (get_str(r, "name"), get_str(r, "url")))
        .collect())
}

pub fn remote_url(dir: &Path) -> Result<Option<String>> {
    Ok(remotes(dir)?
        .into_iter()
        .find(|(n, _)| n == REMOTE)
        .map(|(_, u)| u))
}

pub fn add(cfg: &Config, url: &str) -> Result<()> {
    let dir = cfg.archive_dir();
    archive::ensure(&dir, &cfg.machine, dolt::now_ms())?;
    if let Some(existing) = remote_url(&dir)? {
        bail!("already syncing with {existing}; run `agentd sync remove` first");
    }
    dolt::dolt(&dir, &["remote", "add", REMOTE, url])?;
    Ok(())
}

pub fn remove(cfg: &Config) -> Result<()> {
    let dir = cfg.archive_dir();
    if remote_url(&dir)?.is_some() {
        dolt::dolt(&dir, &["remote", "remove", REMOTE])?;
    }
    let _ = std::fs::remove_file(cfg.force_push_flag());
    Ok(())
}

#[derive(Debug, Serialize, Default, PartialEq)]
pub struct SyncResult {
    pub remote: Option<String>,
    pub pulled: bool,
    pub pushed: bool,
    pub force_pushed: bool,
    /// the remote's history was rewritten (a redact elsewhere): reset to it
    pub reset: bool,
    /// own files restored after a reset (deleted from disk, kept by this Mac)
    pub restored: usize,
}

fn remote_has_branch(dir: &Path) -> Result<bool> {
    Ok(dolt::count(
        dir,
        &format!("SELECT COUNT(*) AS n FROM dolt_remote_branches WHERE name = 'remotes/{REMOTE}/{BRANCH}'"),
    )? > 0)
}

fn unrelated(err: &str) -> bool {
    let e = err.to_lowercase();
    e.contains("no common ancestor") || e.contains("unrelated") || e.contains("common ancestor")
}

pub fn run(cfg: &Config, literals: &[String], vault: Option<&Vault>) -> Result<SyncResult> {
    let dir = cfg.archive_dir();
    let mut res = SyncResult {
        remote: remote_url(&dir)?,
        ..Default::default()
    };
    if res.remote.is_none() {
        return Ok(res); // local-only
    }
    if archive::dirty(&dir)? {
        bail!("archive has uncommitted changes; run `agentd ingest` first");
    }
    if cfg.force_push_flag().exists() {
        // This Mac rewrote history (redact). Its archive already holds every
        // machine's rows as of its last pull, redacted; publish it as-is.
        dolt::dolt(&dir, &["push", "--force", REMOTE, BRANCH])?;
        std::fs::remove_file(cfg.force_push_flag())?;
        res.force_pushed = true;
        res.pushed = true;
        return Ok(res);
    }
    dolt::dolt(&dir, &["fetch", REMOTE])?;
    if remote_has_branch(&dir)? {
        match dolt::dolt(&dir, &["merge", &format!("{REMOTE}/{BRANCH}")]) {
            Ok(_) => res.pulled = true,
            Err(e) if unrelated(&e.to_string()) => {
                res.restored = reset_to_remote(cfg, literals, vault)?;
                res.reset = true;
                res.pulled = true;
            }
            Err(e) => {
                let _ = dolt::dolt(&dir, &["merge", "--abort"]);
                return Err(e);
            }
        }
        if dolt::count(&dir, "SELECT COUNT(*) AS n FROM dolt_conflicts")? > 0 {
            let _ = dolt::dolt(&dir, &["merge", "--abort"]);
            bail!("merge produced conflicts, which shouldn't happen (rows are keyed by machine); aborted, nothing changed");
        }
    }
    dolt::dolt(&dir, &["push", REMOTE, BRANCH])?;
    res.pushed = true;
    Ok(res)
}

/// The remote was rewritten by another Mac's redact. Keep this Mac's own
/// archive-only files (deleted from disk, so a re-ingest can't bring them
/// back), reset to the remote, then write those back and re-ingest.
fn reset_to_remote(cfg: &Config, literals: &[String], vault: Option<&Vault>) -> Result<usize> {
    let dir = cfg.archive_dir();
    let mine: Vec<archive::ArchivedFile> = archive::archived_files(&dir)?
        .into_iter()
        .filter(|f| f.machine == cfg.machine)
        .collect();
    let mut keep: Vec<Entry> = vec![];
    for kind in KINDS {
        let gone: Vec<&archive::ArchivedFile> = mine
            .iter()
            .filter(|f| {
                f.kind == kind
                    && !sources::kind_root(kind, &cfg.roots)
                        .join(&f.rel_path)
                        .exists()
            })
            .collect();
        if gone.is_empty() {
            continue;
        }
        let texts = archive::texts_of(&dir, &cfg.machine, kind)?;
        for f in gone {
            let stored = texts.get(&f.key()).cloned().unwrap_or_default();
            keep.push(Entry {
                kind: f.kind.clone(),
                rel_path: f.rel_path.clone(),
                session_id: f.session_id.clone(),
                title: f.title.clone(),
                mtime_ms: f.mtime_ms,
                text: redact::redact_text(&stored, literals, vault)?.0,
                trim_tail: false,
            });
        }
    }
    dolt::dolt(&dir, &["reset", "--hard", &format!("{REMOTE}/{BRANCH}")])?;
    let present: std::collections::HashSet<String> = archive::archived_files(&dir)?
        .iter()
        .map(archive::ArchivedFile::key)
        .collect();
    keep.retain(|e| !present.contains(&format!("{}\t{}\t{}", cfg.machine, e.kind, e.rel_path)));
    let restored = keep.len();
    let at = dolt::now_ms();
    archive::write_entries(&dir, &cfg.machine, keep)?;
    archive::commit(
        &dir,
        &cfg.machine,
        &format!("restore {restored} archive-only file(s) after a remote redact"),
        at,
    )?;
    archive::ingest(cfg, literals, vault)?;
    Ok(restored)
}
