//! Where things live. Everything can be overridden by environment variables,
//! which is also how the tests point agentd at throwaway directories.

use std::path::PathBuf;
use std::process::Command;

#[derive(Clone, Debug)]
pub struct Roots {
    /// ~/.claude/projects: Claude Code transcripts and per-project memory
    pub claude_projects: PathBuf,
    /// ~/.codex/sessions: Codex rollout transcripts
    pub codex_sessions: PathBuf,
    /// ~/.codex: holds Codex's memories/ and memories_v2/ folders
    pub codex_home: PathBuf,
    /// ~/.pi/agent/sessions: pi transcripts
    pub pi_sessions: PathBuf,
}

#[derive(Clone, Debug)]
pub struct Config {
    /// AGENTD_HOME, default ~/.local/share/agentd
    pub home: PathBuf,
    /// This Mac's name in the archive. Every row is keyed by it, so two Macs
    /// never write the same row and syncing never conflicts.
    pub machine: String,
    pub roots: Roots,
}

fn env_path(key: &str, default: PathBuf) -> PathBuf {
    std::env::var_os(key).map(PathBuf::from).unwrap_or(default)
}

impl Config {
    pub fn load() -> Config {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        Config {
            home: env_path("AGENTD_HOME", home.join(".local/share/agentd")),
            machine: std::env::var("AGENTD_MACHINE")
                .ok()
                .map(|m| sanitize_machine(&m))
                .unwrap_or_else(machine_name),
            roots: Roots {
                claude_projects: env_path("AGENTD_CLAUDE_PROJECTS", home.join(".claude/projects")),
                codex_sessions: env_path("AGENTD_CODEX_SESSIONS", home.join(".codex/sessions")),
                codex_home: env_path("AGENTD_CODEX_HOME", home.join(".codex")),
                pi_sessions: env_path("AGENTD_PI_SESSIONS", home.join(".pi/agent/sessions")),
            },
        }
    }

    pub fn archive_dir(&self) -> PathBuf {
        self.home.join("archive")
    }
    pub fn view_db(&self) -> PathBuf {
        self.home.join("view.sqlite")
    }
    /// Extra strings to redact. Outside archive/ on purpose: the archive is
    /// what gets pushed to a remote; this file never is.
    pub fn literals_file(&self) -> PathBuf {
        self.home.join("redact-literals")
    }
    /// Set after a redact rewrote history; the next sync force-pushes.
    pub fn force_push_flag(&self) -> PathBuf {
        self.home.join("force-push-pending")
    }
}

/// Machine names are spliced into SQL and used as commit emails, so they are
/// reduced to [A-Za-z0-9-].
pub fn sanitize_machine(raw: &str) -> String {
    let s: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(63)
        .collect();
    if s.is_empty() {
        "unknown".into()
    } else {
        s
    }
}

fn machine_name() -> String {
    for cmd in [
        &["scutil", "--get", "LocalHostName"][..],
        &["hostname", "-s"][..],
    ] {
        if let Ok(out) = Command::new(cmd[0]).args(&cmd[1..]).output() {
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if out.status.success() && !name.is_empty() {
                return sanitize_machine(&name);
            }
        }
    }
    "unknown".into()
}

#[cfg(test)]
mod tests {
    use super::sanitize_machine;

    #[test]
    fn machine_names_are_sql_safe() {
        assert_eq!(sanitize_machine("Pat's MacBook Pro"), "Pat-s-MacBook-Pro");
        assert_eq!(sanitize_machine("x'; DROP"), "x---DROP");
        assert_eq!(sanitize_machine("''"), "unknown");
    }
}
