//! agentd: archive, redact, sync and browse your coding-agent sessions.

mod archive;
mod config;
mod dolt;
mod hub;
mod redact;
mod server;
mod service;
mod sources;
mod sync;
mod transcript;
mod tunnel;
mod vault;
mod view;

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::Config;
use std::io::{BufRead, IsTerminal, Write};
use std::process::ExitCode;

const DEFAULT_PORT: u16 = 3850;

#[derive(Parser)]
#[command(
    name = "agentd",
    version,
    about = "Archive, redact, sync and browse your coding-agent sessions (Claude Code, Codex, pi)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Archive new and changed transcripts and memory (redacting secrets)
    Ingest,
    /// What a scheduled run does: ingest, sync (if a remote is set), refresh the browser
    Run,
    /// Sync this Mac's archive with a remote; with no subcommand, sync now
    Sync {
        #[command(subcommand)]
        action: Option<SyncCmd>,
    },
    /// Serve the archive browser and API on 127.0.0.1
    Serve {
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
        /// the API's bearer token, read from this file (created, random and
        /// 0600, if missing); default AGENTD_HOME/serve-token. Browsers get
        /// it from `agentd open`.
        #[arg(long)]
        token_file: Option<std::path::PathBuf>,
    },
    /// Open the browser signed in (hands it `agentd serve`'s token)
    Open {
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
    },
    /// PASS/FAIL check of the archive against disk, itself and the browser (exit 1 on failure)
    Verify {
        #[arg(long)]
        json: bool,
    },
    /// Count secrets (by kind, never values) in the archive and in the agents' own files
    Secrets {
        #[arg(long)]
        json: bool,
    },
    /// Re-redact everything stored and drop the archive's history
    Redact {
        /// First read an extra string to redact from stdin (input hidden)
        #[arg(long)]
        add: bool,
    },
    /// Print a redacted secret from this Mac's vault
    Reveal { id: String },
    /// The sync hub, for the server your Macs sync through (see README)
    Hub {
        #[command(subcommand)]
        action: HubCmd,
    },
    /// Install or remove the LaunchAgents (serve + a run every 30 minutes)
    Service {
        #[command(subcommand)]
        action: ServiceCmd,
    },
    /// Show where agentd keeps its data
    Paths,
}

#[derive(Subcommand)]
enum SyncCmd {
    /// Sync with a remote: ssh://[user@]host[:22]/agents[?port=50052] for an agentd hub
    /// reached through an SSH tunnel, or any Dolt remote URL (s3://…, file://…, http://…)
    Add {
        url: String,
        /// remotes-API user (ssh:// remotes default to the hub's "agentd",
        /// whose password is read from the hub over SSH at each sync);
        /// otherwise a password, if needed, comes from AGENTD_REMOTE_PASSWORD
        #[arg(long)]
        user: Option<String>,
    },
    /// Stop syncing (the local archive is kept)
    Remove,
    /// Show the remote, if any
    Status,
    /// Create this Mac's sync key (once) and print the line for the server's authorized_keys
    Key {
        /// the hub's remotes port the key may forward to
        #[arg(long, default_value_t = tunnel::DEFAULT_REMOTES_PORT)]
        port: u16,
    },
}

#[derive(Subcommand)]
enum HubCmd {
    /// Run the sync hub in the foreground (Dolt sql-server; SQL on 127.0.0.1)
    Serve {
        /// data directory (default: $SRV_DATA_DIR, else ~/.local/share/agentd-hub)
        #[arg(long)]
        dir: Option<std::path::PathBuf>,
        #[arg(long, default_value = "agents")]
        database: String,
        #[arg(long, default_value_t = tunnel::DEFAULT_REMOTES_PORT)]
        remotes_port: u16,
        #[arg(long, default_value_t = 3851)]
        sql_port: u16,
        /// answer GET /health on 127.0.0.1 (default: $PORT, if set)
        #[arg(long)]
        health_port: Option<u16>,
    },
}

#[derive(Subcommand)]
enum ServiceCmd {
    Install {
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
    },
    Uninstall,
}

fn vault(cfg: &Config) -> Result<vault::Vault> {
    vault::Vault::open(&cfg.home.join("vault.sqlite"), &cfg.machine)
}

fn by_kind(c: &redact::Counts) -> String {
    let mut v: Vec<_> = c.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1));
    let s = v
        .iter()
        .map(|(k, n)| format!("{k} {n}"))
        .collect::<Vec<_>>()
        .join(", ");
    if s.is_empty() {
        "none".into()
    } else {
        s
    }
}

fn read_hidden(prompt: &str) -> Result<String> {
    let tty = std::io::stdin().is_terminal();
    if tty {
        eprint!("{prompt}");
        std::io::stderr().flush()?;
        let _ = std::process::Command::new("stty")
            .arg("-echo")
            .stdin(std::process::Stdio::inherit())
            .status();
    }
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    if tty {
        let _ = std::process::Command::new("stty")
            .arg("echo")
            .stdin(std::process::Stdio::inherit())
            .status();
        eprintln!();
    }
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

fn mark(failed: bool) -> &'static str {
    if failed {
        "FAIL"
    } else {
        "ok  "
    }
}

fn sample(v: &[String]) -> String {
    if v.is_empty() {
        String::new()
    } else {
        format!(
            "  e.g. {}",
            v.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
        )
    }
}

fn run(cli: Cli) -> Result<bool> {
    let cfg = Config::load();
    let literals = redact::load_literals(&cfg.literals_file());
    match cli.cmd {
        Cmd::Ingest => {
            let v = vault(&cfg)?;
            let r = archive::ingest(&cfg, &literals, Some(&v))?;
            println!(
                "archived {} changed file(s), {} unchanged{}",
                r.ingested,
                r.unchanged,
                if r.committed { ", committed" } else { "" }
            );
            if redact::total(&r.redacted) > 0 {
                println!("redacted on the way in: {}", by_kind(&r.redacted));
            }
            let u = view::update(&cfg, &cfg.view_db())?;
            println!("browser: {} refreshed of {}", u.refreshed, u.total);
        }
        Cmd::Run => {
            let v = vault(&cfg)?;
            let r = archive::ingest(&cfg, &literals, Some(&v))?;
            println!("ingest: {} changed, {} unchanged", r.ingested, r.unchanged);
            let s = sync::run(&cfg, &literals, Some(&v));
            match &s {
                Ok(s) if s.remote.is_none() => println!("sync: local-only (no remote)"),
                Ok(s) => println!(
                    "sync: {}{}{}",
                    if s.force_pushed {
                        "force-pushed redacted history"
                    } else if s.pushed {
                        "pulled and pushed"
                    } else {
                        "nothing"
                    },
                    if s.reset {
                        "; remote history was rewritten elsewhere, reset to it"
                    } else {
                        ""
                    },
                    if s.restored > 0 {
                        format!("; restored {} archive-only file(s)", s.restored)
                    } else {
                        String::new()
                    },
                ),
                Err(e) => eprintln!("sync failed: {e:#}"),
            }
            let u = view::update(&cfg, &cfg.view_db())?;
            println!("browser: {} refreshed of {}", u.refreshed, u.total);
            return Ok(s.is_ok());
        }
        Cmd::Sync { action } => {
            match action {
                Some(SyncCmd::Add { url, user }) => {
                    sync::add(&cfg, &url, user)?;
                    println!("syncing with {url}; run `agentd sync` (or wait for the next scheduled run)");
                }
                Some(SyncCmd::Remove) => {
                    sync::remove(&cfg)?;
                    println!("sync removed; the local archive is unchanged");
                }
                Some(SyncCmd::Status) => {
                    match sync::remote_url(&cfg.archive_dir())? {
                        Some(u) => {
                            let s = tunnel::load(&cfg)?;
                            match &s.ssh {
                            Some(t) => println!(
                                "remote: {u}\nthrough: ssh tunnel to {} (port {}) → hub port {}{}",
                                t.target,
                                t.ssh_port,
                                t.remote_port,
                                t.key.as_ref().map(|k| format!(", key {}", k.display())).unwrap_or_default()
                            ),
                            None => println!("remote: {u}"),
                        }
                            println!("machine: {}", cfg.machine);
                        }
                        None => println!("local-only (no remote); machine: {}", cfg.machine),
                    }
                }
                Some(SyncCmd::Key { port }) => {
                    let line = tunnel::ensure_key(&cfg, port)?;
                    eprintln!(
                        "key: {} (dedicated to agentd; no passphrase so it works unattended)",
                        tunnel::key_path(&cfg).display()
                    );
                    eprintln!("add this line to ~/.ssh/authorized_keys on the server (forwarding to port {port} only; its one command prints the hub's sync password):");
                    println!("{line}");
                }
                None => {
                    let v = vault(&cfg)?;
                    let s = sync::run(&cfg, &literals, Some(&v))?;
                    println!("{}", serde_json::to_string_pretty(&s)?);
                    view::update(&cfg, &cfg.view_db())?;
                }
            }
        }
        Cmd::Serve { port, token_file } => {
            let file = token_file.unwrap_or_else(|| cfg.serve_token_file());
            server::serve(&cfg, port, server::load_token(&file)?)?
        }
        Cmd::Open { port } => {
            std::fs::create_dir_all(&cfg.home)?;
            // a one-time code, not the token: the URL lands in browser history
            let code = server::new_open_code(&cfg)?;
            let opener = std::env::var("AGENTD_OPEN").unwrap_or_else(|_| "open".into());
            let status = std::process::Command::new(&opener)
                .arg(format!("http://127.0.0.1:{port}/#code={code}"))
                .status()?;
            if !status.success() {
                anyhow::bail!("{opener} failed ({status})");
            }
            eprintln!(
                "opened http://127.0.0.1:{port}; the link signs this browser in once, within {}s",
                server::OPEN_CODE_TTL_MS / 1000
            );
        }
        Cmd::Hub {
            action:
                HubCmd::Serve {
                    dir,
                    database,
                    remotes_port,
                    sql_port,
                    health_port,
                },
        } => {
            let home = std::env::var_os("HOME")
                .map(std::path::PathBuf::from)
                .unwrap_or_default();
            let dir = dir
                .or_else(|| std::env::var_os("SRV_DATA_DIR").map(std::path::PathBuf::from))
                .unwrap_or_else(|| home.join(".local/share/agentd-hub"));
            let health_port =
                health_port.or_else(|| std::env::var("PORT").ok().and_then(|p| p.parse().ok()));
            hub::serve(hub::HubOpts {
                dir,
                database,
                remotes_port,
                sql_port,
                health_port,
            })?;
        }
        Cmd::Verify { json } => {
            let v = vault(&cfg)?;
            let r = archive::verify(&cfg, &literals, Some(&v))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&r)?);
                return Ok(r.ok);
            }
            println!("archive  {}  (machine {})", r.archive_dir, r.machine);
            println!(
                "{} last ingest      {}",
                mark(r.last_ingest.is_none()),
                r.last_ingest
                    .as_deref()
                    .unwrap_or("never: run `agentd ingest`")
            );
            println!(
                "{} committed        {}",
                mark(!r.clean),
                if r.clean {
                    "no uncommitted changes"
                } else {
                    "uncommitted changes"
                }
            );
            println!(
                "{} coverage         {}/{} files on disk archived as-is; {} missed{}",
                mark(!r.missed.is_empty()),
                r.on_disk - r.missed.len() - r.pending.len(),
                r.on_disk,
                r.missed.len(),
                sample(&r.missed)
            );
            println!(
                "ok   pending          {} changed after the last ingest (next run)",
                r.pending.len()
            );
            println!(
                "{} byte-exact       {} on-disk files the archive doesn't rebuild exactly{}",
                mark(!r.mismatched.is_empty()),
                r.mismatched.len(),
                sample(&r.mismatched)
            );
            println!(
                "{} integrity        {} of {} archived files off their recorded SHA-256{}",
                mark(!r.corrupt.is_empty()),
                r.corrupt.len(),
                r.archived,
                sample(&r.corrupt)
            );
            println!(
                "{} secrets          {} archived files still holding a secret{}",
                mark(!r.secrets.is_empty()),
                r.secrets.len(),
                sample(&r.secrets)
            );
            println!(
                "{} browser          {} files missing from or behind the browser's view{}",
                mark(!r.stale_view.is_empty()),
                r.stale_view.len(),
                sample(&r.stale_view)
            );
            println!("ok   kept             {} of this Mac's files the agent deleted; {} from other Macs", r.archive_only.len(), r.other_machines);
            println!("{}", if r.ok { "PASS" } else { "FAIL" });
            return Ok(r.ok);
        }
        Cmd::Secrets { json } => {
            let s = archive::scan_secrets(&cfg, &literals)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&s)?);
            } else {
                println!(
                    "archive   {} file(s) with unredacted secrets: {}",
                    s.archive_files.len(),
                    by_kind(&s.archive)
                );
                println!(
                    "on disk   {} agent file(s) with secrets: {}",
                    s.disk_files.len(),
                    by_kind(&s.disk)
                );
                println!("          (the agents' own files; agentd archives them redacted and never edits them)");
            }
        }
        Cmd::Redact { add } => {
            let mut literals = literals;
            if add {
                let lit = read_hidden("string to redact everywhere (input hidden): ")?;
                redact::add_literal(&cfg.literals_file(), &lit)?;
                literals = redact::load_literals(&cfg.literals_file());
                eprintln!(
                    "saved to {} (0600); future ingests redact it too",
                    cfg.literals_file().display()
                );
            }
            let v = vault(&cfg)?;
            let r = archive::redact_archive(&cfg, &literals, Some(&v))?;
            println!(
                "rewrote {} file(s); redacted {}; dropped {} old commit(s)",
                r.files,
                by_kind(&r.redacted),
                r.commits_dropped
            );
            view::rebuild(&cfg, &cfg.view_db())?;
            if sync::remote_url(&cfg.archive_dir())?.is_some() {
                println!(
                    "the next sync force-pushes the rewritten history; other Macs reset to it"
                );
            }
        }
        Cmd::Reveal { id } => match vault(&cfg)?.reveal(&id)? {
            Some((kind, value)) => {
                if std::io::stdout().is_terminal() {
                    eprintln!("{kind} {id}:");
                }
                println!("{}", vault::display_value(&value));
            }
            None => anyhow::bail!(
                "{id} isn't in this Mac's vault (it may have been redacted on another Mac)"
            ),
        },
        Cmd::Service { action } => match action {
            ServiceCmd::Install { port } => service::install(port)?,
            ServiceCmd::Uninstall => service::uninstall()?,
        },
        Cmd::Paths => {
            println!("home      {}", cfg.home.display());
            println!("archive   {}", cfg.archive_dir().display());
            println!("browser   {}", cfg.view_db().display());
            let n = vault(&cfg)
                .and_then(|v| v.len())
                .map(|n| format!(" ({n} secrets)"))
                .unwrap_or_default();
            println!("vault     {}{n}", cfg.home.join("vault.sqlite").display());
            println!("literals  {}", cfg.literals_file().display());
            println!(
                "machine   {}  (fixed in {})",
                cfg.machine,
                cfg.machine_file().display()
            );
        }
    }
    Ok(true)
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("agentd: {e:#}");
            ExitCode::FAILURE
        }
    }
}
