//! A thin wrapper over the `dolt` CLI. Rows go in through `dolt table
//! import` from JSON files, so transcript text never becomes SQL; the only
//! values spliced into SQL are kinds from a fixed list, sanitized machine
//! names, UUIDs, SAFE_PATH-checked paths and integers.

use anyhow::{anyhow, Context, Result};
use serde_json::{Map, Value};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

pub type Row = Map<String, Value>;

pub fn dolt(dir: &Path, args: &[&str]) -> Result<String> {
    dolt_env(dir, args, &[])
}

/// Passwords go through the environment (DOLT_CLI_PASSWORD,
/// DOLT_REMOTE_PASSWORD), never argv, where `ps` would show them.
pub fn dolt_env(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Result<String> {
    let out = Command::new("dolt")
        .args(args)
        .envs(env.iter().copied())
        .current_dir(dir)
        .output()
        .context("running dolt (is it installed? brew install dolt)")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let err = if err.is_empty() {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        } else {
            err
        };
        return Err(anyhow!("dolt {}: {}", args.first().unwrap_or(&""), err));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn select(dir: &Path, sql: &str) -> Result<Vec<Row>> {
    let out = dolt(dir, &["sql", "-r", "json", "-q", sql])?;
    let out = out.trim();
    if out.is_empty() {
        return Ok(vec![]);
    }
    let v: Value = serde_json::from_str(out).context("parsing dolt json output")?;
    Ok(v.get("rows")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().filter_map(|r| r.as_object().cloned()).collect())
        .unwrap_or_default())
}

pub fn count(dir: &Path, sql: &str) -> Result<i64> {
    Ok(select(dir, sql)?
        .first()
        .and_then(|r| r.values().next())
        .and_then(as_i64)
        .unwrap_or(0))
}

/// Upsert rows into a table: `dolt table import -u` from a temp JSON file.
pub fn import(dir: &Path, table: &str, rows: &[Value]) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    static N: AtomicU64 = AtomicU64::new(0);
    let tmp = std::env::temp_dir().join(format!(
        "agentd-import-{}-{}.json",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(
        &tmp,
        serde_json::to_vec(&serde_json::json!({ "rows": rows }))?,
    )?;
    let res = dolt(
        dir,
        &["table", "import", "-u", table, tmp.to_str().unwrap()],
    );
    let _ = std::fs::remove_file(&tmp);
    res.map(|_| ())
}

pub fn as_i64(v: &Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .or_else(|| v.as_f64().map(|f| f as i64))
}

pub fn get_str(r: &Row, k: &str) -> String {
    r.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

pub fn get_i64(r: &Row, k: &str) -> i64 {
    r.get(k).and_then(as_i64).unwrap_or(0)
}

/// dolt_log dates look like "2026-11-20 10:11:12.345" (UTC).
pub fn parse_date_ms(s: &str) -> Option<i64> {
    let iso = format!("{}Z", s.replacen(' ', "T", 1));
    humantime::parse_rfc3339_weak(&iso)
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
}

pub fn iso(ms: i64) -> String {
    humantime::format_rfc3339_millis(
        std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms.max(0) as u64),
    )
    .to_string()
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
