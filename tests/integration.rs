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
    let rows = a.dolt("SELECT machine, agentd_version FROM syncs ORDER BY machine");
    assert!(rows.contains("mac-a") && rows.contains("mac-b"), "{rows}");
    assert!(rows.contains(env!("CARGO_PKG_VERSION")), "{rows}");

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
    // the rewrite must carry b's sync record, before b syncs again
    let after_redact = base.path().join("clone-after-redact");
    let cloned = Command::new("dolt")
        .args(["clone", &url, after_redact.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        cloned.status.success(),
        "{}",
        String::from_utf8_lossy(&cloned.stderr)
    );
    let synced = Command::new("dolt")
        .args(["sql", "-r", "csv", "-q", "SELECT machine FROM syncs"])
        .current_dir(&after_redact)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&synced.stdout).contains("mac-b"),
        "redact dropped b's syncs row: {}",
        String::from_utf8_lossy(&synced.stdout)
    );
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

    // after the redact, b (which went through reset_to_remote) and a sync again
    let before = b.dolt("SELECT synced_at_ms FROM syncs WHERE machine = 'mac-b'");
    std::thread::sleep(std::time::Duration::from_millis(50));
    b.run(&["run"]);
    a.run(&["run"]);
    for m in [&a, &b] {
        let rows = m.dolt("SELECT machine FROM syncs ORDER BY machine");
        assert!(
            rows.contains("mac-a") && rows.contains("mac-b"),
            "{}: {rows}",
            m.name
        );
    }
    let after = b.dolt("SELECT synced_at_ms FROM syncs WHERE machine = 'mac-b'");
    let ms = |s: &str| s.lines().last().unwrap().parse::<i64>().unwrap();
    assert!(ms(&after) > ms(&before), "{before} -> {after}");
    let a_view = a.dolt("SELECT synced_at_ms FROM syncs WHERE machine = 'mac-b'");
    assert_eq!(ms(&a_view), ms(&after), "a pulled b's post-restore sync");
}

#[test]
fn sync_works_on_an_archive_created_before_the_syncs_table() {
    if !have_dolt() {
        eprintln!("skipping: dolt not installed");
        return;
    }
    let base = tempfile::tempdir().unwrap();
    let remote = base.path().join("remote");
    std::fs::create_dir_all(&remote).unwrap();
    let url = format!("file://{}", remote.display());
    let a = Mac::new(base.path(), "mac-a", KEY_A);
    a.write_claude(
        "-Users-x-alpha",
        UUID_A,
        &session("claude-opus-5-5", "/Users/x/alpha", "q", "ls", "out"),
    );
    a.run(&["ingest"]);
    a.run(&["sync", "add", &url]);
    // simulate an archive from before this change
    a.dolt("DROP TABLE syncs");
    a.dolt("CALL DOLT_COMMIT('-A', '-m', 'pre-syncs archive')");
    a.run(&["sync"]);
    assert!(a.dolt("SELECT machine FROM syncs").contains("mac-a"));
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
    let rows = Command::new("dolt")
        .args(["sql", "-r", "csv", "-q", "SELECT machine FROM syncs"])
        .current_dir(&clone)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&rows.stdout).contains("mac-a"));
}

#[test]
fn sync_commits_do_not_move_last_ingest() {
    if !have_dolt() {
        eprintln!("skipping: dolt not installed");
        return;
    }
    let base = tempfile::tempdir().unwrap();
    let remote = base.path().join("remote");
    std::fs::create_dir_all(&remote).unwrap();
    let url = format!("file://{}", remote.display());
    let a = Mac::new(base.path(), "mac-a", KEY_A);
    a.write_claude(
        "-Users-x-alpha",
        UUID_A,
        &session("claude-opus-5-5", "/Users/x/alpha", "q", "ls", "out"),
    );
    a.run(&["ingest"]);
    a.run(&["sync", "add", &url]);
    let before = a.verify();
    assert_eq!(before["ok"], true, "{before}");
    std::thread::sleep(std::time::Duration::from_millis(1100));
    a.run(&["sync"]);
    a.run(&["sync"]);
    let after = a.verify();
    assert_eq!(after["ok"], true, "{after}");
    assert_eq!(after["last_ingest"], before["last_ingest"]);
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
    use std::os::unix::fs::PermissionsExt;

    // the token is on by default: AGENTD_HOME/serve-token, 0600
    let token_file = a.home.join("serve-token");
    assert_eq!(
        std::fs::metadata(&token_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let token = std::fs::read_to_string(&token_file).unwrap();
    let bearer = format!("Authorization: Bearer {token}");

    // open without it: health, and the page (no data; it asks for the token)
    assert_eq!(curl(&[&format!("{base_url}/api/health")]), "200");
    assert_eq!(curl(&[&format!("{base_url}/")]), "200");
    // everything else needs it, whatever the Host
    for path in [
        "/api/sessions",
        "/api/session?machine=mac-a&kind=claude&path=x",
        "/api/raw?machine=mac-a&kind=claude&path=x",
    ] {
        assert_eq!(curl(&[&format!("{base_url}{path}")]), "401", "{path}");
        assert_eq!(
            curl(&[
                "-H",
                "Authorization: Bearer wrong",
                &format!("{base_url}{path}")
            ]),
            "401",
            "{path}"
        );
    }
    assert_eq!(
        curl(&[
            "-X",
            "POST",
            "-H",
            "X-Agentd-Reveal: 1",
            &format!("{base_url}/api/reveal?id=000000000000")
        ]),
        "401"
    );
    assert_eq!(
        curl(&["-H", &bearer, &format!("{base_url}/api/sessions")]),
        "200"
    );

    // with the token, the browser guards still hold
    assert_eq!(
        curl(&[
            "-H",
            &bearer,
            "-H",
            "Host: evil.example",
            &format!("{base_url}/api/sessions")
        ]),
        "403"
    );
    assert_eq!(
        curl(&[
            "-H",
            &bearer,
            "-X",
            "POST",
            &format!("{base_url}/api/reveal?id=000000000000")
        ]),
        "403"
    );
    assert_eq!(
        curl(&[
            "-H",
            &bearer,
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
            "-H",
            &bearer,
            "-X",
            "POST",
            "-H",
            "X-Agentd-Reveal: 1",
            &format!("{base_url}/api/reveal?id=000000000000")
        ]),
        "404"
    );
    assert_eq!(
        curl(&[
            "-H",
            &bearer,
            &format!("{base_url}/api/session?machine=mac-a&kind=claude&path=../../etc/passwd")
        ]),
        "404"
    );
    // agentd open: a one-time code in the URL, traded once for the token
    let out = a
        .cmd(&["open", "--port", &port.to_string()])
        .env("AGENTD_OPEN", "/bin/echo")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let url = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(!url.contains(&token), "the token must never be in the URL");
    let code = url
        .split_once("#code=")
        .map(|(_, c)| c.to_string())
        .unwrap_or_else(|| panic!("no code in {url}"));
    let login = |code: &str, host: Option<&str>| {
        let mut c = Command::new("curl");
        c.args(["-s", "-X", "POST", "-w", "\n%{http_code}"]);
        if let Some(h) = host {
            c.args(["-H", &format!("Host: {h}")]);
        }
        let out = c
            .arg(format!("{base_url}/api/login?code={code}"))
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    assert!(login("wrong", None).ends_with("403"));
    assert!(login(&code, Some("evil.example")).ends_with("403"));
    let ok = login(&code, None);
    assert!(ok.ends_with("200"), "{ok}");
    let body: Value = serde_json::from_str(ok.rsplit_once('\n').unwrap().0).unwrap();
    assert_eq!(body["token"], token.as_str());
    assert!(login(&code, None).ends_with("403"), "a code works once");

    server.kill().unwrap();
    server.wait().unwrap();

    // --token-file elsewhere (kmini-home's srv data dir); a restart keeps it
    let other = base.path().join("srv/token");
    for _ in 0..2 {
        let mut server = a
            .cmd(&[
                "serve",
                "--port",
                &port.to_string(),
                "--token-file",
                other.to_str().unwrap(),
            ])
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(400));
        let t = std::fs::read_to_string(&other).unwrap();
        assert_ne!(t, token);
        let b = format!("Authorization: Bearer {t}");
        assert_eq!(
            curl(&["-H", &b, &format!("{base_url}/api/sessions")]),
            "200"
        );
        assert_eq!(
            curl(&["-H", &bearer, &format!("{base_url}/api/sessions")]),
            "401"
        );
        server.kill().unwrap();
        server.wait().unwrap();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The hub runs in its own process group so the test can stop it and the
/// dolt sql-server it started together (launchd does the same for a job).
struct Hub {
    child: std::process::Child,
    remotes: u16,
}

impl Drop for Hub {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &format!("-{}", self.child.id())])
            .status();
        let _ = self.child.wait();
    }
}

/// `ssh_home` stands in for the SSH user's home on the server: the hub keeps
/// the sync password under it, and fake_ssh runs commands there.
fn start_hub(dir: &Path, ssh_home: &Path) -> Hub {
    use std::os::unix::process::CommandExt;
    let (remotes, sql, health) = (free_port(), free_port(), free_port());
    let child = Command::new(env!("CARGO_BIN_EXE_agentd"))
        .args(["hub", "serve", "--dir", dir.to_str().unwrap()])
        .env(
            "AGENTD_HUB_PASSWORD_FILE",
            ssh_home.join(".config/agentd-hub/agentd-password"),
        )
        .args([
            "--remotes-port",
            &remotes.to_string(),
            "--sql-port",
            &sql.to_string(),
        ])
        .args(["--health-port", &health.to_string()])
        .process_group(0)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        let out = Command::new("curl")
            .args(["-s", "-o", "/dev/null", "-w", "%{http_code}"])
            .arg(format!("http://127.0.0.1:{health}/health"))
            .output()
            .unwrap();
        if String::from_utf8_lossy(&out.stdout) == "200" {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "hub never became healthy"
        );
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    Hub { child, remotes }
}

#[test]
fn two_macs_sync_through_an_ssh_tunnel_to_a_hub() {
    if !have_dolt() || Command::new("python3").arg("--version").output().is_err() {
        eprintln!("skipping: needs dolt and python3");
        return;
    }
    let base = tempfile::tempdir().unwrap();
    let hub_dir = base.path().join("hub");
    let ssh_home = base.path().join("server-home");
    let hub = start_hub(&hub_dir, &ssh_home);

    // the hub locked root down before opening the remotes port
    let pw = hub_dir.join("root-password");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&pw).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let anon = Command::new("dolt")
        .args([
            "clone",
            &format!("http://127.0.0.1:{}/agents", hub.remotes),
            base.path().join("anon").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!anon.status.success(), "anonymous clone must be refused");
    assert!(
        String::from_utf8_lossy(&anon.stderr).contains("Access denied"),
        "{}",
        String::from_utf8_lossy(&anon.stderr)
    );
    // and the Macs' user needs its password too: loopback is shared with
    // whatever else runs on the server (containers)
    let agentd_pw = ssh_home.join(".config/agentd-hub/agentd-password");
    assert_eq!(
        std::fs::metadata(&agentd_pw).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let no_pw = Command::new("dolt")
        .args([
            "clone",
            "--user",
            "agentd",
            &format!("http://127.0.0.1:{}/agents", hub.remotes),
            base.path().join("no-pw").to_str().unwrap(),
        ])
        .env("DOLT_REMOTE_PASSWORD", "")
        .output()
        .unwrap();
    assert!(
        !no_pw.status.success(),
        "passwordless agentd clone must be refused"
    );

    let fake_ssh = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fake_ssh.py");
    let url = format!("ssh://agentd@hub-host/agents?port={}", hub.remotes);
    let a = Mac::new(base.path(), "mac-a", KEY_A);
    let b = Mac::new(base.path(), "mac-b", KEY_B);
    a.write_claude(
        "-Users-x-alpha",
        UUID_A,
        &session("claude-opus-5-5", "/Users/x/alpha", "a asks", "ls", "ok"),
    );
    b.write_claude(
        "-Users-x-beta",
        UUID_B,
        &session("claude-fable-5", "/Users/x/beta", "b asks", "pwd", "/tmp"),
    );
    let run = |m: &Mac, args: &[&str]| {
        let out = m
            .cmd(args)
            .env("AGENTD_SSH", &fake_ssh)
            .env("FAKE_SSH_HOME", &ssh_home)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success(),
            "agentd {args:?} on {}: {text}",
            m.name
        );
        text
    };
    for m in [&a, &b] {
        run(m, &["sync", "add", &url]);
        assert!(run(m, &["sync", "status"]).contains("ssh tunnel to agentd@hub-host"));
    }
    // a is first at the new hub: it publishes over the hub's empty first commit
    let out = run(&a, &["run"]);
    assert!(out.contains("force-pushed"), "{out}");
    let out = run(&b, &["run"]);
    assert!(out.contains("pulled and pushed"), "{out}");
    run(&a, &["run"]);
    for m in [&a, &b] {
        let machines: Vec<String> = m
            .sessions("")
            .iter()
            .map(|r| r["machine"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(machines, ["mac-a", "mac-b"], "{} sees both Macs", m.name);
        assert_eq!(m.verify()["ok"], true, "{}: {}", m.name, m.verify());
    }
    // the tunnel is gone after each sync: nothing left listening locally
    let s: Value =
        serde_json::from_slice(&std::fs::read(a.home.join("sync.json")).unwrap()).unwrap();
    let local = s["ssh"]["local_port"].as_u64().unwrap() as u16;
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", local)).is_err(),
        "tunnel left open"
    );

    // a Mac whose key the server refuses: the sync fails loudly, the archive is untouched
    let c = Mac::new(base.path(), "mac-c", KEY_A);
    c.write_claude(
        "-Users-x-gamma",
        UUID_C,
        &session("claude-opus-5-5", "/Users/x/gamma", "c asks", "ls", "ok"),
    );
    run(&c, &["ingest"]);
    run(
        &c,
        &[
            "sync",
            "add",
            &format!("ssh://denied@hub-host/agents?port={}", hub.remotes),
        ],
    );
    let out = c
        .cmd(&["run"])
        .env("AGENTD_SSH", &fake_ssh)
        .env("FAKE_SSH_HOME", &ssh_home)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("Permission denied (publickey)"), "{text}");
    assert_eq!(c.verify()["ok"], true, "{}", c.verify());
}
