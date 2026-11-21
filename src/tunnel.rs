//! Sync settings and the SSH tunnel.
//!
//! `agentd sync add ssh://[user@]host[:22]/agents?port=50052` means: the
//! remote is a Dolt remotes API listening on the server's loopback, reached
//! through `ssh -L` for the length of each sync. Nothing new is exposed on the
//! server, and access is whatever SSH allows: a dedicated key per Mac (see
//! `agentd sync key`) restricted to that one forward.
//!
//! The settings live in AGENTD_HOME/sync.json, outside the Dolt repo, so they
//! are never synced. Dolt itself only ever sees http://127.0.0.1:<local>/db.

use crate::config::Config;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const DEFAULT_REMOTES_PORT: u16 = 50052;
pub const HUB_USER: &str = "agentd";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SyncConfig {
    /// User for the remotes API (`dolt push --user`). An agentd hub accepts
    /// "agentd" with no password, from loopback only.
    pub user: Option<String>,
    pub ssh: Option<SshTunnel>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshTunnel {
    /// `user@host` or `host`, as ssh takes it
    pub target: String,
    pub ssh_port: u16,
    /// the private key; None = ssh's defaults
    pub key: Option<PathBuf>,
    /// the remotes API port on the server's loopback
    pub remote_port: u16,
    /// the local end Dolt talks to; fixed when the remote is added, because
    /// the URL Dolt stores contains it
    pub local_port: u16,
}

fn path(cfg: &Config) -> PathBuf {
    cfg.home.join("sync.json")
}

pub fn load(cfg: &Config) -> Result<SyncConfig> {
    match std::fs::read(path(cfg)) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).context("reading sync.json")?),
        Err(_) => Ok(SyncConfig::default()),
    }
}

pub fn save(cfg: &Config, s: &SyncConfig) -> Result<()> {
    std::fs::create_dir_all(&cfg.home)?;
    std::fs::write(path(cfg), serde_json::to_vec_pretty(s)?)?;
    Ok(())
}

pub fn clear(cfg: &Config) {
    let _ = std::fs::remove_file(path(cfg));
}

pub fn key_path(cfg: &Config) -> PathBuf {
    cfg.home.join("ssh/id_ed25519")
}

fn free_port() -> Result<u16> {
    Ok(TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port())
}

/// `ssh://[user@]host[:ssh-port]/<database>[?port=<remotes port>&key=<path>]`
/// → the tunnel settings and the URL Dolt should store.
pub fn parse_ssh_url(url: &str, default_key: Option<PathBuf>) -> Result<(SshTunnel, String)> {
    let rest = url.strip_prefix("ssh://").context("not an ssh:// url")?;
    let (main, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (authority, db) = main
        .split_once('/')
        .context("ssh url needs a database: ssh://host/agents")?;
    if db.is_empty()
        || !db
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        bail!("database name must be letters, digits, _ or -");
    }
    let (target, ssh_port) = match authority.rsplit_once(':') {
        Some((t, p)) => (t, p.parse::<u16>().context("bad ssh port")?),
        None => (authority, 22),
    };
    // passed to ssh as an argument: refuse anything it could read as an option
    if target.is_empty()
        || target.starts_with('-')
        || !target
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._-".contains(c))
    {
        bail!("bad ssh target {target:?}");
    }
    let mut remote_port = DEFAULT_REMOTES_PORT;
    let mut key = default_key;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        match pair.split_once('=') {
            Some(("port", v)) => remote_port = v.parse().context("bad remotes port")?,
            Some(("key", v)) => key = Some(PathBuf::from(v)),
            _ => bail!("unknown ssh url option {pair:?} (port, key)"),
        }
    }
    let local_port = free_port()?;
    let dolt_url = format!("http://127.0.0.1:{local_port}/{db}");
    Ok((
        SshTunnel {
            target: target.into(),
            ssh_port,
            key,
            remote_port,
            local_port,
        },
        dolt_url,
    ))
}

/// The ssh invocation, without the program name.
pub fn ssh_args(t: &SshTunnel, known_hosts: &Path) -> Vec<String> {
    let mut a: Vec<String> = [
        "-N",
        "-T",
        "-o",
        "BatchMode=yes", // never prompt: this runs under launchd
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "StrictHostKeyChecking=accept-new", // trust on first use; a changed key fails
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "ConnectTimeout=10",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    a.extend([
        "-o".into(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
    ]);
    if let Some(k) = &t.key {
        a.extend([
            "-o".into(),
            "IdentitiesOnly=yes".into(),
            "-i".into(),
            k.display().to_string(),
        ]);
    }
    a.extend([
        "-p".into(),
        t.ssh_port.to_string(),
        "-L".into(),
        format!("127.0.0.1:{}:127.0.0.1:{}", t.local_port, t.remote_port),
        t.target.clone(),
    ]);
    a
}

/// An open tunnel; closed when dropped, whatever the sync did.
pub struct Tunnel {
    child: Child,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn open(cfg: &Config, t: &SshTunnel) -> Result<Tunnel> {
    if TcpStream::connect(("127.0.0.1", t.local_port)).is_ok() {
        bail!(
            "local port {} is already in use; re-add the remote to pick another (`agentd sync remove`, then `sync add`)",
            t.local_port
        );
    }
    let known = cfg.home.join("ssh/known_hosts");
    if let Some(dir) = known.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let ssh = std::env::var("AGENTD_SSH").unwrap_or_else(|_| "ssh".into());
    let mut child = Command::new(&ssh)
        .args(ssh_args(t, &known))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {ssh}"))?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait()? {
            let mut err = String::new();
            if let Some(mut e) = child.stderr.take() {
                let _ = e.read_to_string(&mut err);
            }
            bail!(
                "ssh tunnel to {} exited ({status}): {}",
                t.target,
                err.trim()
            );
        }
        if TcpStream::connect(("127.0.0.1", t.local_port)).is_ok() {
            return Ok(Tunnel { child });
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("ssh tunnel to {} didn't open within 20s", t.target);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Creates the dedicated key (once) and returns the authorized_keys line for
/// the server: forwarding to the hub's loopback port only, no shell, no pty,
/// no agent or X11 forwarding.
pub fn ensure_key(cfg: &Config, remote_port: u16) -> Result<String> {
    let key = key_path(cfg);
    if !key.exists() {
        std::fs::create_dir_all(key.parent().unwrap())?;
        let out = Command::new("ssh-keygen")
            .args([
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                &format!("agentd@{}", cfg.machine),
                "-f",
            ])
            .arg(&key)
            .output()
            .context("running ssh-keygen")?;
        if !out.status.success() {
            bail!(
                "ssh-keygen: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    }
    let public = std::fs::read_to_string(key.with_extension("pub"))?;
    Ok(authorized_keys_line(public.trim(), remote_port))
}

pub fn authorized_keys_line(public_key: &str, remote_port: u16) -> String {
    format!(
        r#"restrict,port-forwarding,permitopen="127.0.0.1:{remote_port}",command="/usr/bin/false" {public_key}"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ssh_urls() {
        let (t, url) = parse_ssh_url("ssh://pat@hub.example:2222/agents?port=50060", None).unwrap();
        assert_eq!(
            (t.target.as_str(), t.ssh_port, t.remote_port, t.key),
            ("pat@hub.example", 2222, 50060, None)
        );
        assert_eq!(url, format!("http://127.0.0.1:{}/agents", t.local_port));
        let (t, _) = parse_ssh_url("ssh://hub.example/agents", Some("/k".into())).unwrap();
        assert_eq!(
            (t.ssh_port, t.remote_port, t.key),
            (22, DEFAULT_REMOTES_PORT, Some("/k".into()))
        );
        let (t, _) = parse_ssh_url("ssh://h/agents?key=/other", Some("/k".into())).unwrap();
        assert_eq!(t.key, Some("/other".into()));
    }

    #[test]
    fn refuses_option_injection_and_bad_names() {
        for bad in [
            "ssh://-oProxyCommand=evil/agents",
            "ssh://host",
            "ssh://host/",
            "ssh://host/../x",
            "ssh://ho st/agents",
            "ssh://host/agents?shell=1",
        ] {
            assert!(parse_ssh_url(bad, None).is_err(), "{bad}");
        }
    }

    #[test]
    fn ssh_args_forward_one_port_and_never_prompt() {
        let t = SshTunnel {
            target: "u@h".into(),
            ssh_port: 22,
            key: Some("/k".into()),
            remote_port: 50052,
            local_port: 40000,
        };
        let a = ssh_args(&t, Path::new("/kh"));
        let s = a.join(" ");
        assert!(
            s.contains("BatchMode=yes") && s.contains("ExitOnForwardFailure=yes"),
            "{s}"
        );
        assert!(s.contains("-L 127.0.0.1:40000:127.0.0.1:50052"), "{s}");
        assert!(
            s.contains("-i /k") && s.contains("UserKnownHostsFile=/kh"),
            "{s}"
        );
        assert_eq!(a.last().unwrap(), "u@h");
    }

    #[test]
    fn authorized_keys_line_is_locked_down() {
        let l = authorized_keys_line("ssh-ed25519 AAAA agentd@m", 50052);
        assert_eq!(
            l,
            r#"restrict,port-forwarding,permitopen="127.0.0.1:50052",command="/usr/bin/false" ssh-ed25519 AAAA agentd@m"#
        );
    }
}
