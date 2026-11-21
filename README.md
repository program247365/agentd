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
| `agentd sync add <url>` / `sync` / `sync status` / `sync remove` | sync with a Dolt remote |
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

A fresh install is local-only. To sync, give every Mac the same
[Dolt remote](https://docs.dolthub.com/concepts/dolt/git/remotes):

```sh
agentd sync add http://my-server:50051/agents     # dolt remotesrv
agentd sync add 's3://bucket/agents?endpoint=…'    # S3, R2, MinIO
agentd sync add file:///Volumes/nas/agents         # a shared folder
```

What crosses the wire is the archive: already redacted, with secrets only
as markers. The remote's operator can read it. Put the remote somewhere only
your machines reach (for `dolt remotesrv`, a private network such as
Tailscale), or use storage you trust.

Each Mac writes only rows keyed by its own name (`AGENTD_MACHINE`, default the
Mac's LocalHostName), so pulls merge cleanly. After `agentd redact` on any Mac,
the next sync force-pushes the rewritten history; every other Mac finds no
common ancestor, resets to it, and re-adds its own files from disk and from
its local copy, so nothing it kept is lost.

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
