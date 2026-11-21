# agentd

Your coding agents delete their own history. Claude Code removes session
transcripts after 30 days by default, and everything an agent ran, read and
answered goes with them. agentd keeps it: a byte-exact, searchable,
secret-redacted archive of every **Claude Code**, **Codex** and **pi**
session (subagents included) and of the agents' **memory**, on each of your
Macs, optionally synced between them.

- **Archive**: every transcript line stored verbatim in a local
  [Dolt](https://github.com/dolthub/dolt) repo. A file rebuilt from the
  archive has the original's SHA-256 (after redaction).
- **Redact**: anything that looks like a secret (private keys; GitHub,
  Anthropic, OpenAI, AWS, Slack, Stripe and Google keys; JWTs; bearer tokens;
  `*_TOKEN=` / `*PASSWORD=`-style values; strings you add) is replaced before
  it is stored, with a marker like `[REDACTED:github-token:3f9a1c0b7e2d]`.
- **Reveal**: the original goes to a local vault (ChaCha20-Poly1305, key in
  the macOS Keychain) that is never synced. `agentd reveal <id>` or the
  browser's reveal button shows it, on the Mac that recorded it.
- **Browse**: `agentd serve` is a local web UI on `127.0.0.1:3850`: page
  through every session, see which agent and which model wrote it, full-text
  search everything including tool calls and output, jump to the match.
- **Sync** (optional): point any number of Macs at one Dolt remote. Rows are
  keyed by machine, so merges never conflict, and a redact on one Mac rewrites
  history everywhere.
- **Verify**: `agentd verify` is a PASS/FAIL check of all of the above.

## Install

```sh
brew install program247365/tap/agentd   # pulls in dolt
agentd service install                  # serve on :3850 + archive every 30 min
open http://127.0.0.1:3850
```

Or from source: `cargo install --path .` (needs `dolt` on PATH).

Also worth doing for Claude Code, so the transcripts exist to archive: set
`"cleanupPeriodDays": 36500` in `~/.claude/settings.json`.

## Commands

| | |
|---|---|
| `agentd run` | what the schedule runs: ingest, sync, refresh the browser |
| `agentd ingest` | archive new and changed files only |
| `agentd serve [--port 3850]` | the browser, on 127.0.0.1 only |
| `agentd verify [--json]` | PASS/FAIL, exit 1 on failure |
| `agentd secrets [--json]` | count secrets by kind (never values), in the archive and in the agents' own files |
| `agentd redact [--add]` | re-redact everything and drop the archive's history; `--add` reads an extra string from stdin |
| `agentd reveal <id>` | print a redacted value from this Mac's vault |
| `agentd sync add <url>` / `sync` / `sync status` / `sync remove` | sync with a remote (`ssh://` for a hub) |
| `agentd sync key` | this Mac's sync key and its restricted `authorized_keys` line |
| `agentd hub serve` | run the sync hub on a server |
| `agentd service install` / `uninstall` | LaunchAgents |
| `agentd paths` | where everything lives |

## What gets archived

| kind | from |
|---|---|
| `claude` | `~/.claude/projects/**/*.jsonl` (sessions and subagents) |
| `codex` | `~/.codex/sessions/**/*.jsonl` |
| `pi` | `~/.pi/agent/sessions/**/*.jsonl` |
| `claude-memory` | `~/.claude/projects/*/memory/**/*.md` |
| `codex-memory` | `~/.codex/memories{,_v2}/**/*.md` |

Data lives in `~/.local/share/agentd` (override with `AGENTD_HOME`):
`archive/` (the Dolt repo, the only thing ever synced), `view.sqlite` (the
browser's search index, derived and rebuildable), `vault.sqlite` (encrypted
originals of redacted secrets), `redact-literals` (your extra strings, 0600).

## Syncing between Macs

A fresh install is local-only. To sync, point every Mac at one remote.

### Your own hub, over SSH (recommended)

Any machine you can SSH into becomes the hub. Nothing new is exposed: the
Macs reach it through an SSH tunnel opened for each sync, with a dedicated
key per Mac that may only forward to the hub's port.

On the server:

```sh
brew install program247365/tap/agentd
agentd hub serve      # foreground: run it under launchd, systemd or your supervisor
```

On each Mac:

```sh
agentd sync key       # makes a key for agentd and prints one line:
                      # restrict,port-forwarding,permitopen="127.0.0.1:50052",command="/usr/bin/false" ssh-ed25519 …
                      # append it to ~/.ssh/authorized_keys on the server
agentd sync add ssh://you@server/agents
agentd sync           # or wait for the scheduled run
```

`ssh://[user@]host[:ssh-port]/<database>[?port=<hub port>&key=<path>]`.
Losing a Mac means deleting one line from `authorized_keys`.

What the hub does (`agentd hub serve [--dir] [--remotes-port 50052] [--sql-port 3851] [--health-port N]`):
it runs `dolt sql-server` with SQL on 127.0.0.1, and before the remotes port
ever opens it sets a random root password (kept 0600 in the hub dir) and
creates an `agentd@localhost` user with no password. The tunnel arrives on
the server's loopback, so it signs in as that user.

Know this about the hub: **Dolt's remotes API listens on every interface**;
there is no option to bind it to loopback. A client that reaches the port
directly is anonymous, which Dolt treats as root, and root's password is
random and never shown. That makes the port useless without SSH, but it is
still open. Block it at the server's firewall if you can.

`--dir` defaults to `$SRV_DATA_DIR`, then `~/.local/share/agentd-hub`;
`--health-port` defaults to `$PORT`; `GET /health` answers 200 while the
database does. So under a supervisor that provides those (like srv), the
service is just `agentd hub serve`.

### Any other Dolt remote

```sh
agentd sync add 's3://bucket/agents?endpoint=…'   # S3, R2, MinIO
agentd sync add file:///Volumes/nas/agents        # a shared folder
agentd sync add http://host:50052/agents --user name   # password: AGENTD_REMOTE_PASSWORD
```

What crosses the wire is the archive: already redacted, with secrets only
as markers. Whoever runs the remote can read it.

### How sync behaves

Each Mac writes only rows keyed by its own name, so pulls merge cleanly.
The name is the Mac's LocalHostName on first run, saved to
`~/.local/share/agentd/machine` so renaming the Mac later changes nothing
(`AGENTD_MACHINE` overrides it). To rename on purpose, edit that file:
rows already archived keep the old name, and the vault's Keychain key is
looked up by the name, so reveal secrets from before first. The first Mac to reach a
new hub publishes over the hub's empty first commit. After `agentd redact`
on any Mac, the next sync force-pushes the rewritten history; every other
Mac finds no common ancestor, resets to it, and re-adds its own files from
disk and from its local copy, so nothing it kept is lost. Any Mac that can
sync can force-push, so back the hub up (`dolt backup`) somewhere else.

## Secrets: what redaction can and can't do

Redaction protects the archive and everything synced from it. It does not
edit the agents' own files (`agentd secrets` counts what's in them), and
anything a command printed was already sent to the model provider as part of
the conversation. Rotate real credentials that show up.

## Development

```sh
make check   # rustfmt, clippy (warnings fail), unit + integration tests
```

Integration tests run the real binary against throwaway directories and two
simulated Macs syncing through a `file://` remote; they need `dolt`.

## License

MIT
