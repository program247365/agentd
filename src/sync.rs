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
use crate::tunnel::{self, SyncConfig};
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

/// `ssh://…` remotes go through a tunnel (see tunnel.rs); anything else is
/// handed to Dolt as-is, optionally with a remotes-API user.
pub fn add(cfg: &Config, url: &str, user: Option<String>) -> Result<()> {
    let dir = cfg.archive_dir();
    archive::ensure(&dir, &cfg.machine, dolt::now_ms())?;
    if let Some(existing) = remote_url(&dir)? {
        bail!("already syncing with {existing}; run `agentd sync remove` first");
    }
    let (dolt_url, settings) = if url.starts_with("ssh://") {
        let key = Some(tunnel::key_path(cfg)).filter(|k| k.exists());
        let (t, dolt_url) = tunnel::parse_ssh_url(url, key)?;
        (
            dolt_url,
            SyncConfig {
                user: Some(user.unwrap_or_else(|| tunnel::HUB_USER.into())),
                ssh: Some(t),
            },
        )
    } else {
        (url.to_string(), SyncConfig { user, ssh: None })
    };
    dolt::dolt(&dir, &["remote", "add", REMOTE, &dolt_url])?;
    tunnel::save(cfg, &settings)?;
    Ok(())
}

pub fn remove(cfg: &Config) -> Result<()> {
    let dir = cfg.archive_dir();
    if remote_url(&dir)?.is_some() {
        dolt::dolt(&dir, &["remote", "remove", REMOTE])?;
    }
    tunnel::clear(cfg);
    let _ = std::fs::remove_file(cfg.force_push_flag());
    Ok(())
}

/// fetch/push against the remote, with the configured user. The password
/// (none, for an agentd hub reached through a tunnel) comes from
/// AGENTD_REMOTE_PASSWORD, via the environment rather than argv.
fn remote(dir: &Path, s: &SyncConfig, verb: &str, rest: &[&str]) -> Result<String> {
    let mut args = vec![verb];
    if let Some(u) = &s.user {
        args.extend(["--user", u.as_str()]);
    }
    args.extend_from_slice(rest);
    let pw = std::env::var("AGENTD_REMOTE_PASSWORD").unwrap_or_default();
    dolt::dolt_env(dir, &args, &[("DOLT_REMOTE_PASSWORD", pw.as_str())])
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

/// A fresh hub database has only its own first commit: no archive yet.
fn remote_has_archive(dir: &Path) -> bool {
    dolt::count(
        dir,
        &format!("SELECT COUNT(*) AS n FROM files AS OF '{REMOTE}/{BRANCH}'"),
    )
    .is_ok()
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
    let settings = tunnel::load(cfg)?;
    // held for the whole sync; closed on return, success or not
    let _tunnel = match &settings.ssh {
        Some(t) => Some(tunnel::open(cfg, t)?),
        None => None,
    };
    if cfg.force_push_flag().exists() {
        // This Mac rewrote history (redact). Its archive already holds every
        // machine's rows as of its last pull, redacted; publish it as-is.
        archive::record_sync(&dir, &cfg.machine, dolt::now_ms())?;
        remote(&dir, &settings, "push", &["--force", REMOTE, BRANCH])?;
        std::fs::remove_file(cfg.force_push_flag())?;
        res.force_pushed = true;
        res.pushed = true;
        return Ok(res);
    }
    remote(&dir, &settings, "fetch", &[REMOTE])?;
    if remote_has_branch(&dir)? && !remote_has_archive(&dir) {
        // the first Mac to reach a new hub publishes its archive over the
        // hub's empty first commit
        archive::record_sync(&dir, &cfg.machine, dolt::now_ms())?;
        remote(&dir, &settings, "push", &["--force", REMOTE, BRANCH])?;
        res.pushed = true;
        res.force_pushed = true;
        return Ok(res);
    }
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
    archive::record_sync(&dir, &cfg.machine, dolt::now_ms())?;
    remote(&dir, &settings, "push", &[REMOTE, BRANCH])?;
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
    archive::ensure(&dir, &cfg.machine, at)?;
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
