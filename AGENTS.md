# agentd

Rust CLI + local web UI that archives coding-agent transcripts and memory
into Dolt, redacts secrets into a local vault, syncs via Dolt remotes.

## Verify

Run `make check` before calling anything done: `cargo fmt --check`,
`cargo clippy --all-targets -D warnings`, `cargo test` (integration tests
drive the real binary and need `dolt` on PATH). Fix the code, not the check.

## Rules that matter

- Transcript text never becomes SQL: rows go in via `dolt table import` from
  JSON. Only fixed kinds, sanitized machine names, UUIDs, `safe_path` paths
  and integers are ever spliced into SQL (`dolt.rs`, `archive.rs`).
- Every row is keyed by `(machine, kind, rel_path)`; a Mac writes only its
  own machine's rows. That's what makes sync conflict-free; don't break it.
- Redaction must stay idempotent (a marker never re-matches a pattern) and
  must keep JSONL lines parseable. Add a test for every new pattern, built
  at runtime so no key-shaped literal is committed.
- The vault and redact-literals live outside `archive/` and are never synced.
- `serve` binds 127.0.0.1, checks Host, and gates reveals behind the
  `X-Agentd-Reveal` header + same-origin; keep all three.
- No personal data in this repo: no hostnames, usernames or server URLs.
