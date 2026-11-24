//! `agentd hub serve`: the sync hub, a Dolt sql-server whose remotes API the
//! Macs push to and pull from. Meant for a home server, reached only through
//! `agentd sync add ssh://…` tunnels.
//!
//! Dolt can't bind the remotes API to loopback (it listens on every
//! interface), so access control is in the users instead, set up before the
//! remotes port ever opens:
//!   - root gets a long random password on first start (kept 0600 in the hub
//!     dir). An anonymous remotes client is treated as root, so without this
//!     anyone who can reach the port can read and write everything.
//!   - `agentd`@`localhost`, the user the Macs sync as, also with a random
//!     password. Loopback alone is not private: containers on the server
//!     (OrbStack, Docker Desktop) reach the host's 127.0.0.1, and so does
//!     every local process. It lives at a fixed path,
//!     ~/.config/agentd-hub/agentd-password (0600), so a Mac can read it over
//!     the same SSH login it tunnels through, at each sync: nothing to copy,
//!     and access to it is exactly access to SSH.
//!
//! Close the port at the firewall too if the server allows it.
//!
//! Startup runs in two phases: the SQL port alone (loopback) to create the
//! database and users, then the full server. It stays in the foreground, and
//! with --health-port answers GET /health with 200 while the database
//! answers, for process supervisors (srv, launchd).

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub struct HubOpts {
    pub dir: PathBuf,
    pub database: String,
    pub remotes_port: u16,
    pub sql_port: u16,
    pub health_port: Option<u16>,
}

pub(crate) fn write_private(path: &Path, contents: &str) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn config_yaml(o: &HubOpts, with_remotes: bool) -> String {
    let mut y = format!(
        "log_level: warning\nlistener:\n  host: 127.0.0.1\n  port: {}\ndata_dir: {}\n",
        o.sql_port,
        o.dir.join("data").display()
    );
    if with_remotes {
        y.push_str(&format!("remotesapi:\n  port: {}\n", o.remotes_port));
    }
    y
}

fn start(o: &HubOpts, with_remotes: bool) -> Result<Child> {
    let cfg = o.dir.join(if with_remotes {
        "server.yaml"
    } else {
        "setup.yaml"
    });
    std::fs::write(&cfg, config_yaml(o, with_remotes))?;
    Command::new("dolt")
        .args(["sql-server", "--config"])
        .arg(&cfg)
        .current_dir(&o.dir)
        .stdin(Stdio::null())
        .spawn()
        .context("starting dolt sql-server (is dolt installed?)")
}

/// Runs SQL against the hub as `user` (password via env, not argv).
fn sql(o: &HubOpts, user: &str, password: &str, query: &str) -> Result<String> {
    let port = o.sql_port.to_string();
    crate::dolt::dolt_env(
        &o.dir,
        &[
            "--host",
            "127.0.0.1",
            "--port",
            &port,
            "--no-tls",
            "--user",
            user,
            "sql",
            "-q",
            query,
        ],
        &[("DOLT_CLI_PASSWORD", password)],
    )
}

fn wait_ready(o: &HubOpts, child: &mut Child, user: &str, password: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait()? {
            bail!("dolt sql-server exited during startup ({status})");
        }
        if sql(o, user, password, "SELECT 1").is_ok() {
            return Ok(());
        }
        if Instant::now() > deadline {
            bail!("dolt sql-server didn't answer within 30s");
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

pub(crate) fn random_password() -> String {
    use chacha20poly1305::aead::{rand_core::RngCore, OsRng};
    let mut b = [0u8; 24];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// The password in `file`, creating it (0600, random) if it doesn't exist.
/// Saved before it is ever set, so it can't be lost.
pub(crate) fn password_file(file: &Path) -> Result<String> {
    if let Ok(s) = std::fs::read_to_string(file) {
        let s = s.trim();
        if !s.is_empty() {
            return Ok(s.to_string());
        }
    }
    let pw = random_password();
    write_private(file, &pw)?;
    Ok(pw)
}

/// Where the agentd user's password lives: AGENTD_HUB_PASSWORD_FILE, else
/// the path Macs read over SSH (tunnel::HUB_PASSWORD_PATH under $HOME).
pub fn agentd_password_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("AGENTD_HUB_PASSWORD_FILE") {
        return Ok(PathBuf::from(p));
    }
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(crate::tunnel::HUB_PASSWORD_PATH.trim_start_matches("~/")))
}

/// Idempotent: the database, the agentd user and its password, and on first
/// start the root password. Runs with the remotes API closed.
fn setup(o: &HubOpts) -> Result<(String, String)> {
    let pw_file = o.dir.join("root-password");
    let existing = std::fs::read_to_string(&pw_file)
        .ok()
        .map(|s| s.trim().to_string());
    // hex from random_password() or a file only this user can write: safe in SQL
    let agentd_file = agentd_password_path()?;
    if let Some(parent) = agentd_file.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let agentd_pw = password_file(&agentd_file)?;
    if !agentd_pw.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail!("{} must be letters and digits only", agentd_file.display());
    }
    let mut child = start(o, false)?;
    let result = (|| {
        let root_pw = existing.clone().unwrap_or_default();
        wait_ready(o, &mut child, "root", &root_pw)?;
        let db = &o.database;
        // ALTER as well as CREATE: hubs from before 0.3.2 made this user with
        // no password
        sql(
            o,
            "root",
            &root_pw,
            &format!(
                "CREATE DATABASE IF NOT EXISTS `{db}`;
                 CREATE USER IF NOT EXISTS 'agentd'@'localhost' IDENTIFIED BY '{agentd_pw}';
                 ALTER USER 'agentd'@'localhost' IDENTIFIED BY '{agentd_pw}';
                 GRANT ALL ON *.* TO 'agentd'@'localhost';
                 GRANT CLONE_ADMIN ON *.* TO 'agentd'@'localhost';"
            ),
        )?;
        if existing.is_none() {
            let pw = random_password();
            write_private(&pw_file, &pw)?; // saved before it's set, so it can't be lost
            sql(
                o,
                "root",
                "",
                &format!("ALTER USER 'root'@'localhost' IDENTIFIED BY '{pw}';"),
            )?;
            return Ok((pw, agentd_pw));
        }
        Ok((root_pw, agentd_pw))
    })();
    let _ = child.kill();
    let _ = child.wait();
    result
}

pub fn serve(o: HubOpts) -> Result<()> {
    if !o
        .database
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        || o.database.is_empty()
    {
        bail!("database name must be letters, digits, _ or -");
    }
    std::fs::create_dir_all(o.dir.join("data"))?;
    std::fs::set_permissions(&o.dir, std::fs::Permissions::from_mode(0o700))?;
    let (root_pw, agentd_pw) = setup(&o)?;
    let mut child = start(&o, true)?;
    wait_ready(&o, &mut child, "root", &root_pw)?;
    eprintln!(
        "agentd hub: database {} on remotes port {} (sql 127.0.0.1:{}, user agentd, password in {}); reach it with agentd sync add ssh://<this host>/{}?port={}",
        o.database, o.remotes_port, o.sql_port,
        agentd_password_path()?.display(),
        o.database, o.remotes_port
    );
    let Some(port) = o.health_port else {
        let status = child.wait()?;
        bail!("dolt sql-server exited ({status})");
    };
    // The child is waited on by a thread; this thread answers health checks.
    let child = std::sync::Arc::new(std::sync::Mutex::new(child));
    {
        let child = child.clone();
        std::thread::spawn(move || loop {
            if let Ok(Some(status)) = child.lock().unwrap().try_wait() {
                eprintln!("dolt sql-server exited ({status})");
                std::process::exit(1);
            }
            std::thread::sleep(Duration::from_millis(500));
        });
    }
    let server = tiny_http::Server::http(("127.0.0.1", port))
        .map_err(|e| anyhow::anyhow!("health port {port}: {e}"))?;
    for req in server.incoming_requests() {
        let ok = req.url() == "/health" && sql(&o, "agentd", &agentd_pw, "SELECT 1").is_ok();
        let resp = tiny_http::Response::from_string(if ok { "ok\n" } else { "not ready\n" })
            .with_status_code(if ok {
                200
            } else if req.url() == "/health" {
                503
            } else {
                404
            });
        let _ = req.respond(resp);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_config_never_opens_the_remotes_port() {
        let o = HubOpts {
            dir: "/hub".into(),
            database: "agents".into(),
            remotes_port: 50052,
            sql_port: 3851,
            health_port: None,
        };
        assert!(!config_yaml(&o, false).contains("remotesapi"));
        let full = config_yaml(&o, true);
        assert!(
            full.contains("remotesapi:\n  port: 50052") && full.contains("host: 127.0.0.1"),
            "{full}"
        );
    }
}
