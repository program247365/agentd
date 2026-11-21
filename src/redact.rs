//! Secret removal. Transcripts keep command output, so a key a tool printed
//! would otherwise be archived (and, once synced, copied) forever. Ingest
//! runs every file through `redact_text`; `agentd redact` re-applies it to
//! what's stored and rewrites history.
//!
//! Patterns favour precision: a false positive silently edits archived
//! text. Anything they miss can be added as a literal. Replacements contain
//! no quote or backslash, and every pattern either excludes backslashes or
//! spans whole escapes, so a redacted JSONL line still parses.

use anyhow::{bail, Result};
use regex::{Captures, Regex};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::OnceLock;

use crate::vault::Vault;

pub type Counts = BTreeMap<String, usize>;

struct Pattern {
    kind: &'static str,
    re: Regex,
    /// env-secret keeps the variable name (group 2) and drops only the value.
    keep_name: bool,
}

/// Group 1 is the token's left boundary and is always put back. Plain \b
/// fails inside JSONL: a line break in tool output is stored as the two
/// characters `\n`, so in `\nAPI_KEY=…` the `n` touches the `A` and there is
/// no word boundary. Order matters: `\\[ntr]` must be tried before the
/// single-character class, or the `n` would be taken as part of the token.
const B: &str = r"(^|\\[ntr]|[^A-Za-z0-9_])";

fn patterns() -> &'static [Pattern] {
    static P: OnceLock<Vec<Pattern>> = OnceLock::new();
    P.get_or_init(|| {
        let p = |kind, body: &str| Pattern { kind, re: Regex::new(&format!("{B}({body})")).unwrap(), keep_name: false };
        vec![
            Pattern {
                kind: "private-key",
                re: Regex::new(r"()(-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----)").unwrap(),
                keep_name: false,
            },
            // sk-ant- before the generic sk- shape
            p("anthropic-key", r"sk-ant-[A-Za-z0-9_-]{20,}"),
            p("openai-key", r"sk-(?:proj-)?[A-Za-z0-9_-]{32,}"),
            p("github-token", r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
            p("aws-access-key", r"(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            p("slack-token", r"xox[abprs]-[A-Za-z0-9-]{10,}"),
            p("stripe-key", r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}"),
            p("google-api-key", r"AIza[0-9A-Za-z_-]{35}\b"),
            p("jwt", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
            p("bearer-token", r"Bearer [A-Za-z0-9._~+/-]{20,}=*"),
            // ENV-style upper-case names, value only. Values exclude quotes,
            // whitespace, backslash, `$` and `[`: so `$(op read …)`,
            // `${{ secrets.X }}` and `"$VAR"` (references, not secrets) are
            // left alone, and an already-redacted value never matches again.
            // (?:\\?["'])? also takes the JSON-escaped quote a transcript stores.
            Pattern {
                kind: "env-secret",
                re: Regex::new(&format!(
                    r#"{B}([A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY)[A-Z0-9_]*\s*[=:]\s*(?:\\?["'])?)([^\s"'\\$\[]{{8,}})"#
                ))
                .unwrap(),
                keep_name: true,
            },
        ]
    })
}

pub fn token(kind: &str) -> String {
    format!("[REDACTED:{kind}]")
}

fn marker(
    kind: &str,
    value: &str,
    vault: Option<&Vault>,
    err: &mut Option<anyhow::Error>,
) -> String {
    match vault {
        None => token(kind),
        Some(v) => match v.store(kind, value) {
            Ok(id) => format!("[REDACTED:{kind}:{id}]"),
            Err(e) => {
                err.get_or_insert(e);
                token(kind)
            }
        },
    }
}

pub fn kinds() -> Vec<&'static str> {
    std::iter::once("literal")
        .chain(patterns().iter().map(|p| p.kind))
        .collect()
}

/// Replaces every secret with a marker; with a vault, the marker carries an
/// id and the original is stored encrypted so it can be revealed later.
/// A literal matches both as typed and as it appears JSON-escaped inside a
/// transcript line (a password containing `"` or `\` is stored escaped).
pub fn redact_text(
    text: &str,
    literals: &[String],
    vault: Option<&Vault>,
) -> Result<(String, Counts)> {
    let mut counts = Counts::new();
    let mut err: Option<anyhow::Error> = None;
    let mut out = text.to_string();
    for lit in literals {
        let escaped = serde_json::to_string(lit).unwrap();
        let escaped = &escaped[1..escaped.len() - 1];
        for form in if escaped == lit {
            vec![lit.as_str()]
        } else {
            vec![lit.as_str(), escaped]
        } {
            let n = out.matches(form).count();
            if n > 0 {
                *counts.entry("literal".into()).or_default() += n;
                let m = marker("literal", form, vault, &mut err);
                out = out.replace(form, &m);
            }
        }
    }
    for p in patterns() {
        let mut n = 0;
        out =
            p.re.replace_all(&out, |c: &Captures| {
                n += 1;
                if p.keep_name {
                    format!(
                        "{}{}{}",
                        &c[1],
                        &c[2],
                        marker(p.kind, &c[3], vault, &mut err)
                    )
                } else {
                    format!("{}{}", &c[1], marker(p.kind, &c[2], vault, &mut err))
                }
            })
            .into_owned();
        if n > 0 {
            *counts.entry(p.kind.into()).or_default() += n;
        }
    }
    match err {
        Some(e) => Err(e),
        None => Ok((out, counts)),
    }
}

/// Counts only (no vault writes): for scans and checks.
pub fn find(text: &str, literals: &[String]) -> Counts {
    redact_text(text, literals, None)
        .map(|r| r.1)
        .unwrap_or_default()
}

pub fn total(counts: &Counts) -> usize {
    counts.values().sum()
}

pub fn merge(into: &mut Counts, from: &Counts) {
    for (k, v) in from {
        *into.entry(k.clone()).or_default() += v;
    }
}

pub fn load_literals(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|s| {
            s.lines()
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn add_literal(path: &Path, literal: &str) -> Result<()> {
    if literal.chars().count() < 4 {
        bail!("refusing a redaction literal under 4 characters (it would shred ordinary text)");
    }
    if literal.contains('\n') {
        bail!("a redaction literal must be a single line");
    }
    // Otherwise redacting would create new matches and never settle.
    if kinds().iter().any(|k| token(k).contains(literal)) {
        bail!("that literal occurs inside a redaction marker; pick a longer, more specific string");
    }
    let mut existing = load_literals(path);
    if existing.iter().any(|l| l == literal) {
        return Ok(());
    }
    existing.push(literal.to_string());
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all((existing.join("\n") + "\n").as_bytes())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Built at runtime so no key-shaped literal is ever committed.
    fn fake(prefix: &str, body: &str, n: usize) -> String {
        format!("{prefix}{}", body.repeat(n))
    }

    #[test]
    fn each_pattern_is_replaced_with_its_marker() {
        let cases = [
            ("github-token", fake("ghp_", "A1b2C3d4", 5)),
            ("anthropic-key", fake("sk-ant-api03-", "x", 40)),
            ("openai-key", fake("sk-proj-", "Z9", 20)),
            ("aws-access-key", format!("AKIA{}", "ABCDEFGHIJ234567")),
            ("slack-token", format!("xoxb-{}", "1234567890-abcdefghij")),
            ("stripe-key", fake("sk_live_", "q", 24)),
            ("google-api-key", fake("AIza", "S", 35)),
            (
                "jwt",
                format!(
                    "eyJ{}.eyJ{}.{}",
                    "hbGciOiJIUzI1NiJ9",
                    "zdWIiOiIxMjM0NTY3ODkwIn0",
                    "s".repeat(20)
                ),
            ),
            ("bearer-token", fake("Bearer ", "t0k3n", 6)),
            (
                "private-key",
                format!(
                    "-----BEGIN {k}-----\\nb3BlbnNz\\n-----END {k}-----",
                    k = "OPENSSH PRIVATE KEY"
                ),
            ),
        ];
        for (kind, secret) in cases {
            let (out, counts) = redact_text(&format!("before {secret} after"), &[], None).unwrap();
            assert_eq!(out, format!("before [REDACTED:{kind}] after"), "{kind}");
            assert_eq!(counts.get(kind), Some(&1), "{kind}");
        }
    }

    #[test]
    fn token_after_json_escaped_line_break_is_caught() {
        let gh = fake("ghp_", "A1b2C3d4", 5);
        let aws = format!("AKIA{}", "ABCDEFGHIJ234567");
        let (out, _) = redact_text(
            &format!(r#""out\n{gh}\nAPI_TOKEN={v}\t{aws}""#, v = "v".repeat(16)),
            &[],
            None,
        )
        .unwrap();
        assert_eq!(
            out,
            r#""out\n[REDACTED:github-token]\nAPI_TOKEN=[REDACTED:env-secret]\t[REDACTED:aws-access-key]""#
        );
    }

    #[test]
    fn env_assignments_keep_the_name() {
        let v = "hunter2correcthorse";
        assert_eq!(
            redact_text(&format!("DB_PASSWORD={v}"), &[], None)
                .unwrap()
                .0,
            "DB_PASSWORD=[REDACTED:env-secret]"
        );
        assert_eq!(
            redact_text(&format!(r#"export API_TOKEN="{v}""#), &[], None)
                .unwrap()
                .0,
            r#"export API_TOKEN="[REDACTED:env-secret]""#
        );
        assert_eq!(
            redact_text(
                &format!(r#"{{"command":"STRIPE_SECRET_KEY=\"{v}\" make"}}"#),
                &[],
                None
            )
            .unwrap()
            .0,
            r#"{"command":"STRIPE_SECRET_KEY=\"[REDACTED:env-secret]\" make"}"#
        );
    }

    #[test]
    fn references_are_not_secrets() {
        for s in [
            r#"POSTHOG_SOURCEMAP_API_KEY="$(op read 'op://Vault/item/password')""#,
            "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
            r#"API_KEY="$API_KEY""#,
            "PASSWORD=short",
            "const apiToken = process.env.API_TOKEN",
            "an ordinary sentence about passwords and tokens",
        ] {
            assert_eq!(
                redact_text(s, &[], None).unwrap(),
                (s.to_string(), Counts::new()),
                "{s}"
            );
        }
    }

    #[test]
    fn redacted_jsonl_still_parses_and_redaction_is_idempotent() {
        let gh = fake("ghp_", "A1b2C3d4", 5);
        let line = serde_json::json!({"content": format!("token={gh}\nDB_PASSWORD=\"{}\"", "p".repeat(12))}).to_string();
        let lits = vec!["my-own-passphrase".to_string()];
        let (once, _) = redact_text(&format!("{line} my-own-passphrase"), &lits, None).unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(
            once.split(" [REDACTED").next().unwrap()
        )
        .is_ok());
        assert!(!once.contains(&gh) && !once.contains(&"p".repeat(12)));
        assert_eq!(total(&find(&once, &lits)), 0);
    }

    #[test]
    fn literals_match_as_typed_and_json_escaped() {
        let lit = r#"pa"ss\word-42"#.to_string();
        let line = serde_json::json!({"text": format!("typed {lit} here")}).to_string();
        let (out, counts) = redact_text(&format!("{lit} | {line}"), &[lit], None).unwrap();
        assert_eq!(counts.get("literal"), Some(&2));
        assert!(
            serde_json::from_str::<serde_json::Value>(out.split(" | ").nth(1).unwrap()).is_ok()
        );
    }

    #[test]
    fn add_literal_is_private_and_guarded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/literals");
        add_literal(&path, "correct-horse-battery").unwrap();
        add_literal(&path, "correct-horse-battery").unwrap();
        assert_eq!(load_literals(&path), vec!["correct-horse-battery"]);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(add_literal(&path, "abc").is_err());
        assert!(add_literal(&path, "two\nlines").is_err());
        assert!(add_literal(&path, "REDACTED").is_err());
    }

    #[test]
    fn with_a_vault_markers_carry_ids_and_values_can_be_revealed() {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::open_with_key(&dir.path().join("v.sqlite"), [3u8; 32], "mac").unwrap();
        let gh = fake("ghp_", "A1b2C3d4", 5);
        let (out, _) =
            redact_text(&format!("a {gh} b DB_PASSWORD=hunter2horse"), &[], Some(&v)).unwrap();
        let ids: Vec<&str> = out
            .split("[REDACTED:")
            .skip(1)
            .map(|m| m.split(']').next().unwrap())
            .collect();
        assert_eq!(ids.len(), 2);
        let (kind, id) = ids[0].split_once(':').unwrap();
        assert_eq!(kind, "github-token");
        assert_eq!(v.reveal(id).unwrap().unwrap().1, gh);
        assert_eq!(
            v.reveal(ids[1].split_once(':').unwrap().1)
                .unwrap()
                .unwrap()
                .1,
            "hunter2horse"
        );
        // idempotent with ids too, and deterministic across runs
        assert_eq!(total(&find(&out, &[])), 0);
        assert_eq!(
            redact_text(&format!("a {gh} b DB_PASSWORD=hunter2horse"), &[], Some(&v))
                .unwrap()
                .0,
            out
        );
    }
}
