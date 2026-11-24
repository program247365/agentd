//! `agentd serve`: the archive browser and its JSON API, on 127.0.0.1 only.
//!
//! Loopback still isn't private from the browser: any web page can send
//! requests to 127.0.0.1. So every request must carry a Host of this server
//! (blocks DNS rebinding), and revealing a secret additionally needs a
//! custom header (a cross-site page can't send one without a CORS preflight,
//! which this server never approves) and, if present, a same-origin Origin.
//! `search` proxies the read-only routes; it never forwards reveals.
//!
//! Nor is loopback private from other programs: containers (OrbStack, Docker
//! Desktop) reach the host's 127.0.0.1 and can send any Host they like. So
//! every API call but /api/health carries `Authorization: Bearer <token>`,
//! the contents of a 0600 file no container mounts (AGENTD_HOME/serve-token
//! unless --token-file says otherwise). The page itself holds no data and is
//! open; `agentd open` gives a browser the token in the URL fragment, and the
//! page keeps it in its own origin's storage (cookies would be shared with
//! every other 127.0.0.1 port, containers' published ones included).
//! agentd-web and search send it from the file.

use crate::archive;
use crate::config::Config;
use crate::vault::{self, Vault};
use crate::view::{self, Query};
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use tiny_http::{Header, Method, Request, Response, Server};

const INDEX_HTML: &str = include_str!("../web/index.html");

fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(b);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_query(url: &str) -> (String, HashMap<String, String>) {
    let (path, qs) = url.split_once('?').unwrap_or((url, ""));
    let params = qs
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect();
    (path.to_string(), params)
}

fn header<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

/// Host must name this server: blocks DNS rebinding.
pub fn host_ok(host: Option<&str>, port: u16) -> bool {
    matches!(host, Some(h) if h == format!("127.0.0.1:{port}") || h == format!("localhost:{port}"))
}

/// The token for `--token-file`, created (random, 0600) if the file is missing.
pub fn load_token(path: &std::path::Path) -> Result<String> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    crate::hub::password_file(path)
}

/// Needs no token: the page (it holds no data; it asks for the token) and
/// the health check.
pub fn open_route(method: &Method, url: &str) -> bool {
    *method == Method::Get
        && matches!(
            parse_query(url).0.as_str(),
            "/" | "/index.html" | "/api/health"
        )
}

/// `Authorization: Bearer <token>`, compared in constant time.
pub fn token_ok(authorization: Option<&str>, token: &str) -> bool {
    let Some(given) = authorization.and_then(|a| a.strip_prefix("Bearer ")) else {
        return false;
    };
    let (a, b) = (given.as_bytes(), token.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Reveal needs the custom header, and any Origin must be this server.
pub fn reveal_ok(custom: Option<&str>, origin: Option<&str>, port: u16) -> bool {
    custom == Some("1")
        && origin.map_or(true, |o| {
            o == format!("http://127.0.0.1:{port}") || o == format!("http://localhost:{port}")
        })
}

fn json_response(status: u16, body: &Value) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(serde_json::to_vec(body).unwrap())
        .with_status_code(status)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap())
}

fn int(p: &HashMap<String, String>, k: &str, d: i64) -> i64 {
    p.get(k).and_then(|v| v.parse().ok()).unwrap_or(d)
}

fn opt(p: &HashMap<String, String>, k: &str) -> Option<String> {
    p.get(k).filter(|v| !v.is_empty()).cloned()
}

pub fn handle(
    cfg: &Config,
    port: u16,
    method: &Method,
    url: &str,
    host: Option<&str>,
    custom: Option<&str>,
    origin: Option<&str>,
) -> (u16, Value, bool) {
    if !host_ok(host, port) {
        return (
            403,
            json!({"error": "wrong Host (agentd only answers 127.0.0.1/localhost)"}),
            false,
        );
    }
    let (path, p) = parse_query(url);
    let db = cfg.view_db();
    let result: Result<(u16, Value)> = (|| match (method, path.as_str()) {
        (Method::Get, "/" | "/index.html") => Ok((200, Value::Null)),
        (Method::Get, "/api/health") => Ok((
            200,
            json!({"ok": true, "version": env!("CARGO_PKG_VERSION"), "machine": cfg.machine}),
        )),
        (Method::Get, "/api/sessions") => {
            if !db.exists() {
                return Ok((503, json!({"error": "no archive yet: run `agentd run`"})));
            }
            let q = Query {
                kind: opt(&p, "kind"),
                model: opt(&p, "model"),
                machine: opt(&p, "machine"),
                q: opt(&p, "q"),
                subagents: p.get("subagents").map(String::as_str) == Some("1"),
                deleted_only: p.get("deleted").map(String::as_str) == Some("1"),
                page: int(&p, "page", 1).max(1) as usize,
                limit: int(&p, "limit", 50).clamp(1, 200) as usize,
            };
            Ok((200, serde_json::to_value(view::list(cfg, &db, &q)?)?))
        }
        (Method::Get, "/api/session") => {
            let s = view::get(
                cfg,
                &db,
                p.get("machine").map(String::as_str).unwrap_or(""),
                p.get("kind").map(String::as_str).unwrap_or(""),
                p.get("path").map(String::as_str).unwrap_or(""),
                int(&p, "offset", 0),
                int(&p, "limit", 200),
            )?;
            Ok(match s {
                Some(s) => (200, serde_json::to_value(s)?),
                None => (404, json!({"error": "no such archived file"})),
            })
        }
        // The stored JSONL itself, a page of lines at a time. The file must
        // already be in the view, so nothing a client sends reaches Dolt
        // unless the archive put it there first.
        (Method::Get, "/api/raw") => {
            let (m, k, rel) = (
                p.get("machine").cloned().unwrap_or_default(),
                p.get("kind").cloned().unwrap_or_default(),
                p.get("path").cloned().unwrap_or_default(),
            );
            if view::get(cfg, &db, &m, &k, &rel, 0, 1)?.is_none() {
                return Ok((404, json!({"error": "no such archived file"})));
            }
            let text = archive::texts_for(&cfg.archive_dir(), &m, &k, std::slice::from_ref(&rel))?
                .remove(&rel)
                .unwrap_or_default();
            let lines: Vec<&str> = text.split('\n').collect();
            let offset = int(&p, "offset", 0).max(0) as usize;
            let limit = int(&p, "limit", 200).clamp(1, 1000) as usize;
            const CAP: usize = 20_000;
            let page: Vec<Value> = lines
                .iter()
                .enumerate()
                .skip(offset)
                .take(limit)
                .map(|(i, l)| {
                    let mut end = l.len().min(CAP);
                    while !l.is_char_boundary(end) {
                        end -= 1;
                    }
                    let t = if end < l.len() {
                        format!("{}… [{} more bytes]", &l[..end], l.len() - end)
                    } else {
                        l.to_string()
                    };
                    json!({"seq": i, "text": t})
                })
                .collect();
            Ok((
                200,
                json!({"total": lines.len(), "offset": offset, "lines": page}),
            ))
        }
        (Method::Post, "/api/reveal") => {
            if !reveal_ok(custom, origin, port) {
                return Ok((
                    403,
                    json!({"error": "reveal needs the X-Agentd-Reveal header from this page"}),
                ));
            }
            let id = p.get("id").cloned().unwrap_or_default();
            if id.len() != 12 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Ok((400, json!({"error": "bad id"})));
            }
            let v = Vault::open(&cfg.home.join("vault.sqlite"), &cfg.machine)?;
            Ok(match v.reveal(&id)? {
                Some((kind, value)) => (
                    200,
                    json!({"id": id, "kind": kind, "value": vault::display_value(&value)}),
                ),
                None => (
                    404,
                    json!({"error": "not in this Mac's vault (it was redacted on another Mac)"}),
                ),
            })
        }
        _ => Ok((404, json!({"error": "not found"}))),
    })();
    match result {
        Ok((200, Value::Null)) => (200, Value::Null, true),
        Ok((status, body)) => (status, body, false),
        Err(e) => (500, json!({"error": e.to_string()}), false),
    }
}

pub fn serve(cfg: &Config, port: u16, token: String) -> Result<()> {
    let server = Server::http(("127.0.0.1", port))
        .map_err(|e| anyhow::anyhow!("listening on 127.0.0.1:{port}: {e}"))?;
    eprintln!("agentd · http://127.0.0.1:{port} (run `agentd open` to sign a browser in)");
    for req in server.incoming_requests() {
        let (status, body, html) = if !open_route(req.method(), req.url())
            && !token_ok(header(&req, "Authorization"), &token)
        {
            (
                401,
                json!({"error": "this server needs its token (agentd open)"}),
                false,
            )
        } else {
            handle(
                cfg,
                port,
                req.method(),
                req.url(),
                header(&req, "Host"),
                header(&req, "X-Agentd-Reveal"),
                header(&req, "Origin"),
            )
        };
        let resp = if html {
            Response::from_data(INDEX_HTML.as_bytes().to_vec())
                .with_header(Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap())
                .with_header(Header::from_bytes("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:").unwrap())
        } else {
            json_response(status, &body)
        };
        let _ = req.respond(resp);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_reveal_guards() {
        assert!(host_ok(Some("127.0.0.1:3850"), 3850));
        assert!(host_ok(Some("localhost:3850"), 3850));
        assert!(!host_ok(Some("evil.example:3850"), 3850));
        assert!(!host_ok(None, 3850));
        assert!(reveal_ok(Some("1"), Some("http://127.0.0.1:3850"), 3850));
        assert!(reveal_ok(Some("1"), None, 3850));
        assert!(!reveal_ok(None, Some("http://127.0.0.1:3850"), 3850));
        assert!(!reveal_ok(Some("1"), Some("https://evil.example"), 3850));
    }

    #[test]
    fn only_the_page_and_health_are_open() {
        assert!(open_route(&Method::Get, "/"));
        assert!(open_route(&Method::Get, "/index.html"));
        assert!(open_route(&Method::Get, "/api/health"));
        assert!(!open_route(&Method::Post, "/"));
        assert!(!open_route(&Method::Get, "/api/sessions"));
        assert!(!open_route(&Method::Post, "/api/reveal"));
    }

    #[test]
    fn token_guard() {
        assert!(token_ok(Some("Bearer abc123"), "abc123"));
        assert!(!token_ok(Some("Bearer abc124"), "abc123"));
        assert!(!token_ok(Some("Bearer abc12"), "abc123"));
        assert!(!token_ok(Some("abc123"), "abc123"));
        assert!(!token_ok(None, "abc123"));
    }

    #[test]
    fn query_decoding() {
        let (path, p) = parse_query("/api/session?path=-Users-x%2Fa+b.jsonl&kind=claude");
        assert_eq!(path, "/api/session");
        assert_eq!(p["path"], "-Users-x/a b.jsonl");
        assert_eq!(p["kind"], "claude");
    }
}
