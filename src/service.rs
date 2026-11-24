//! `agentd service install|uninstall`: two LaunchAgents in the user's
//! session. `serve` stays up; `run` (ingest, sync, refresh the view) fires
//! every 30 minutes and at login.

use anyhow::{bail, Result};
use std::path::PathBuf;
use std::process::Command;

const SERVE: &str = "com.program247365.agentd.serve";
const RUN: &str = "com.program247365.agentd.run";

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// The path to launch. Homebrew's Cellar path changes with every version,
/// so prefer the stable `bin` symlink when this binary is reached through it.
fn executable() -> Result<PathBuf> {
    let current = std::env::current_exe()?.canonicalize()?;
    for dir in ["/opt/homebrew/bin", "/usr/local/bin"] {
        let link = PathBuf::from(dir).join("agentd");
        if link.canonicalize().ok().as_ref() == Some(&current) {
            return Ok(link);
        }
    }
    Ok(current)
}

fn uid() -> Result<String> {
    let out = Command::new("id").arg("-u").output()?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn plist(label: &str, args: &[&str], keep_alive: bool, interval: Option<u32>, exe: &str) -> String {
    let logs = home().join("Library/Logs");
    let args = std::iter::once(exe)
        .chain(args.iter().copied())
        .map(|a| format!("    <string>{}</string>", xml_escape(a)))
        .collect::<Vec<_>>()
        .join("\n");
    let schedule = match (keep_alive, interval) {
        (true, _) => "  <key>KeepAlive</key>\n  <true/>".to_string(),
        (false, Some(s)) => format!("  <key>StartInterval</key>\n  <integer>{s}</integer>"),
        _ => String::new(),
    };
    let name = label.rsplit('.').next().unwrap_or(label);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{args}
  </array>
  <key>RunAtLoad</key>
  <true/>
{schedule}
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>StandardOutPath</key>
  <string>{out}</string>
  <key>StandardErrorPath</key>
  <string>{out}</string>
</dict>
</plist>
"#,
        out = xml_escape(
            &logs
                .join(format!("agentd-{name}.log"))
                .display()
                .to_string()
        ),
    )
}

pub fn install(port: u16) -> Result<()> {
    let exe = executable()?;
    let exe = exe.to_str().unwrap_or("agentd");
    let dir = home().join("Library/LaunchAgents");
    std::fs::create_dir_all(&dir)?;
    std::fs::create_dir_all(home().join("Library/Logs"))?;
    let port = port.to_string();
    let domain = format!("gui/{}", uid()?);
    for (label, body) in [
        (
            SERVE,
            plist(SERVE, &["serve", "--port", &port], true, None, exe),
        ),
        (RUN, plist(RUN, &["run"], false, Some(1800), exe)),
    ] {
        let path = dir.join(format!("{label}.plist"));
        std::fs::write(&path, body)?;
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("{domain}/{label}")])
            .output();
        let out = Command::new("launchctl")
            .args(["bootstrap", &domain, path.to_str().unwrap()])
            .output()?;
        if !out.status.success() {
            bail!(
                "launchctl bootstrap {label}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        println!("installed {label} → {}", path.display());
    }
    println!("browser: run `agentd open` (signs your browser in to http://127.0.0.1:{port})");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let domain = format!("gui/{}", uid()?);
    for label in [SERVE, RUN] {
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("{domain}/{label}")])
            .output();
        let path = home()
            .join("Library/LaunchAgents")
            .join(format!("{label}.plist"));
        if path.exists() {
            std::fs::remove_file(&path)?;
            println!("removed {label}");
        }
    }
    Ok(())
}
