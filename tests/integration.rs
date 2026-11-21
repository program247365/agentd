//! End-to-end: the real binary against throwaway Macs. Two simulated
//! machines sync through a `file://` Dolt remote standing in for a server.
//! Needs `dolt` on PATH; skipped (with a note) when it isn't.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

const KEY_A: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const KEY_B: &str = "0202020202020202020202020202020202020202020202020202020202020202";
const UUID_A: &str = "11111111-1111-4111-8111-111111111111";
const UUID_B: &str = "22222222-2222-4222-8222-222222222222";
const UUID_C: &str = "33333333-3333-4333-8333-333333333333";

fn have_dolt() -> bool {
    Command::new("dolt")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

struct Mac {
    name: &'static str,
    key: &'static str,
    home: PathBuf,
    claude: PathBuf,
    pi: PathBuf,
    root: PathBuf,
}

impl Mac {
    fn new(base: &Path, name: &'static str, key: &'static str) -> Mac {
        let root = base.join(name);
        let m = Mac {
            name,
            key,
            home: root.join("agentd"),
            claude: root.join("claude/projects"),
            pi: root.join("pi/sessions"),
            root: root.clone(),
        };
        std::fs::create_dir_all(&m.claude).unwrap();
        std::fs::create_dir_all(&m.pi).unwrap();
        m
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_agentd"));
        c.args(args)
            .env("AGENTD_HOME", &self.home)
            .env("AGENTD_MACHINE", self.name)
            .env("AGENTD_VAULT_KEY", self.key)
            .env("AGENTD_CLAUDE_PROJECTS", &self.claude)
            .env("AGENTD_CODEX_SESSIONS", self.root.join("codex/sessions"))
            .env("AGENTD_CODEX_HOME", self.root.join("codex"))
            .env("AGENTD_PI_SESSIONS", &self.pi);
        c
    }

    fn run(&self, args: &[&str]) -> String {
        let out = self.cmd(args).output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success(),
            "agentd {args:?} on {} failed:\n{text}",
            self.name
        );
        text
    }

    fn verify(&self) -> Value {
        let out = self.cmd(&["verify", "--json"]).output().unwrap();
        serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)))
    }

    fn write_claude(&self, project: &str, id: &str, lines: &[Value]) -> PathBuf {
        let p = self.claude.join(project).join(format!("{id}.jsonl"));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            lines
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        )
        .unwrap();
        p
    }

    fn sessions(&self, q: &str) -> Vec<Value> {
        let db = self.home.join("view.sqlite");
        let conn = rusqlite_lite(&db);
        let _ = q;
        conn
    }

    fn dolt(&self, sql: &str) -> String {
        let out = Command::new("dolt")
            .args(["sql", "-r", "csv", "-q", sql])
            .current_dir(self.home.join("archive"))
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

/// The view is checked through `agentd serve`'s own query code in unit
/// tests; here it's enough to read the sessions table with the sqlite3 CLI.
fn rusqlite_lite(db: &Path) -> Vec<Value> {
    let out = Command::new("sqlite3")
        .args(["-json", db.to_str().unwrap(), "SELECT machine, kind, rel_path, title, models FROM sessions ORDER BY machine, rel_path"])
        .output()
        .unwrap();
    serde_json::from_slice(&out.stdout).unwrap_or_default()
}

fn session(model: &str, cwd: &str, prompt: &str, command: &str, output: &str) -> Vec<Value> {
    vec![
        json!({"type":"user","cwd":cwd,"timestamp":"2026-01-01T00:00:00Z","message":{"role":"user","content":prompt}}),
        json!({"type":"assistant","timestamp":"2026-01-01T00:00:01Z","message":{"role":"assistant","model":model,"content":[{"type":"tool_use","name":"Bash","input":{"command":command}}]}}),
        json!({"type":"user","timestamp":"2026-01-01T00:00:02Z","message":{"role":"user","content":[{"type":"tool_result","content":output}]}}),
    ]
}

fn fake_token() -> String {
    format!("ghp_{}", "A1b2C3d4".repeat(5)) // built at runtime: no key-shaped literal in the repo
}

#[test]
fn deleted_transcript_survives_with_tool_steps_and_secrets_go_to_the_vault() {
    if !have_dolt() {
        eprintln!("skipping: dolt not installed");
        return;
    }
    let base = tempfile::tempdir().unwrap();
    let a = Mac::new(base.path(), "mac-a", KEY_A);
    let token = fake_token();
    let file = a.write_claude(
        "-Users-x-alpha",
        UUID_A,
        &session(
            "claude-opus-5-5",
            "/Users/x/alpha",
            "deploy please",
            "flyctl deploy --remote-only",
            &format!("pushing with\n{token}\ndone v202"),
        ),
    );
    std::fs::create_dir_all(a.claude.join("-Users-x-alpha/memory")).unwrap();
    std::fs::write(
        a.claude.join("-Users-x-alpha/memory/deploy.md"),
        "---\nname: fly-deploy\n---\nUse flyctl.\n",
    )
    .unwrap();

    let out = a.run(&["ingest"]);
    assert!(out.contains("archived 2 changed file(s)"), "{out}");
    assert!(out.contains("github-token 1"), "{out}");
    assert_eq!(a.verify()["ok"], true, "{}", a.verify());

    // the token never reached Dolt, in any commit
    assert!(a
        .dolt(&format!(
            "SELECT COUNT(*) FROM dolt_history_file_lines WHERE line LIKE '%{token}%'"
        ))
        .ends_with("0\n"));
    // but the marker's id reveals it from this Mac's vault
    let stored = a.dolt("SELECT line FROM file_lines WHERE line LIKE '%REDACTED:github-token:%'");
    let id = stored.split("REDACTED:github-token:").nth(1).unwrap()[..12].to_string();
    assert_eq!(a.run(&["reveal", &id]).trim(), token);

    // the agent deletes its transcript; the archive keeps all of it
    std::fs::remove_file(&file).unwrap();
    a.run(&["run"]);
    let v = a.verify();
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(
        v["archive_only"],
        json!([format!("claude:-Users-x-alpha/{UUID_A}.jsonl")])
    );
    let kept = a.dolt("SELECT line FROM file_lines WHERE kind = 'claude' AND seq = 1");
    assert!(
        kept.contains("flyctl deploy --remote-only"),
        "tool call kept: {kept}"
    );
    let rows = a.sessions("");
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows
        .iter()
        .any(|r| r["kind"] == "claude-memory" && r["title"] == "fly-deploy"));
    assert!(rows.iter().any(|r| r["models"] == "claude-opus-5-5"));
}

#[test]
fn two_macs_sync_through_a_remote_and_a_redact_propagates() {
    if !have_dolt() {
        eprintln!("skipping: dolt not installed");
        return;
    }
    let base = tempfile::tempdir().unwrap();
    let remote = base.path().join("remote");
    std::fs::create_dir_all(&remote).unwrap();
    let url = format!("file://{}", remote.display());
    let a = Mac::new(base.path(), "mac-a", KEY_A);
    let b = Mac::new(base.path(), "mac-b", KEY_B);
    a.write_claude(
        "-Users-x-alpha",
        UUID_A,
        &session(
            "claude-opus-5-5",
            "/Users/x/alpha",
            "a's question",
            "ls",
            "the wifi password is otter-9931-falls",
        ),
    );
    let b_file = b.write_claude(
        "-Users-x-beta",
        UUID_B,
        &session(
            "claude-fable-5",
            "/Users/x/beta",
            "b's question",
            "pwd",
            "/tmp",
        ),
    );

    for m in [&a, &b] {
        m.run(&["ingest"]);
        m.run(&["sync", "add", &url]);
    }
    a.run(&["run"]); // first push creates the remote branch
    b.run(&["run"]); // b merges a's rows and pushes its own
    a.run(&["run"]); // a merges b's
    for m in [&a, &b] {
        let rows = m.sessions("");
        let machines: Vec<&str> = rows
            .iter()
            .map(|r| r["machine"].as_str().unwrap())
            .collect();
        assert_eq!(
            machines,
            ["mac-a", "mac-b"],
            "{} sees both Macs: {rows:?}",
            m.name
        );
        let v = m.verify();
        assert_eq!(v["ok"], true, "{}: {v}", m.name);
        assert_eq!(v["other_machines"], 1);
    }

    // b deletes its transcript after it's been synced; it must survive a's redact
    std::fs::remove_file(&b_file).unwrap();
    b.run(&["run"]);

    // a learns a secret it should have redacted, and purges it everywhere
    let mut add = a
        .cmd(&["redact", "--add"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    add.stdin
        .take()
        .unwrap()
        .write_all(b"otter-9931-falls\n")
        .unwrap();
    assert!(add.wait().unwrap().success());
    let out = a.run(&["run"]);
    assert!(out.contains("force-pushed"), "{out}");
    // meanwhile b archived a session it hasn't synced, then the agent deleted
    // it: the reset to a's rewritten history must not lose it
    let unsynced = b.write_claude(
        "-Users-x-beta",
        UUID_C,
        &session(
            "claude-fable-5",
            "/Users/x/beta",
            "unsynced",
            "date",
            "today",
        ),
    );
    b.run(&["ingest"]);
    std::fs::remove_file(&unsynced).unwrap();
    let out = b.run(&["run"]);
    assert!(out.contains("reset to it"), "{out}");
    assert!(out.contains("restored 1 archive-only file(s)"), "{out}");

    // gone from b's archive and history, and from the remote's
    for m in [&a, &b] {
        assert!(
            m.dolt("SELECT COUNT(*) FROM dolt_history_file_lines WHERE line LIKE '%otter-9931%'")
                .ends_with("0\n"),
            "{}",
            m.name
        );
        let v = m.verify();
        assert_eq!(v["ok"], true, "{}: {v}", m.name);
    }
    let clone = base.path().join("clone");
    let out = Command::new("dolt")
        .args(["clone", &url, clone.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hist = Command::new("dolt")
        .args([
            "sql",
            "-r",
            "csv",
            "-q",
            "SELECT COUNT(*) FROM dolt_history_file_lines WHERE line LIKE '%otter-9931%'",
        ])
        .current_dir(&clone)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&hist.stdout).ends_with("0\n"),
        "remote history still has it"
    );
    // both of b's deleted-on-disk sessions survived the reset, synced or not
    let b_rows = b.sessions("");
    assert_eq!(
        b_rows.iter().filter(|r| r["machine"] == "mac-b").count(),
        2,
        "{b_rows:?}"
    );
    assert_eq!(b.verify()["archive_only"].as_array().unwrap().len(), 2);
}

#[test]
fn server_refuses_foreign_hosts_and_unguarded_reveals() {
    if !have_dolt() {
        eprintln!("skipping: dolt not installed");
        return;
    }
    let base = tempfile::tempdir().unwrap();
    let a = Mac::new(base.path(), "mac-a", KEY_A);
    a.write_claude(
        "-Users-x-alpha",
        UUID_A,
        &session("claude-opus-5-5", "/Users/x/alpha", "q", "ls", "ok"),
    );
    a.run(&["ingest"]);
    let port = 38000 + (std::process::id() % 1000) as u16;
    let mut server = a
        .cmd(&["serve", "--port", &port.to_string()])
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(400));
    let curl = |args: &[&str]| {
        let out = Command::new("curl")
            .args(["-s", "-o", "/dev/null", "-w", "%{http_code}"])
            .args(args)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let base_url = format!("http://127.0.0.1:{port}");
    assert_eq!(curl(&[&format!("{base_url}/api/health")]), "200");
    assert_eq!(
        curl(&[
            "-H",
            "Host: evil.example",
            &format!("{base_url}/api/sessions")
        ]),
        "403"
    );
    assert_eq!(
        curl(&[
            "-X",
            "POST",
            &format!("{base_url}/api/reveal?id=000000000000")
        ]),
        "403"
    );
    assert_eq!(
        curl(&[
            "-X",
            "POST",
            "-H",
            "X-Agentd-Reveal: 1",
            "-H",
            "Origin: https://evil.example",
            &format!("{base_url}/api/reveal?id=000000000000")
        ]),
        "403"
    );
    assert_eq!(
        curl(&[
            "-X",
            "POST",
            "-H",
            "X-Agentd-Reveal: 1",
            &format!("{base_url}/api/reveal?id=000000000000")
        ]),
        "404"
    );
    assert_eq!(
        curl(&[&format!(
            "{base_url}/api/session?machine=mac-a&kind=claude&path=../../etc/passwd"
        )]),
        "404"
    );
    server.kill().unwrap();
    server.wait().unwrap();
}
