//! One reader for all three transcript formats. Turns a JSONL file into
//! ordered events (what was said, thought, run and returned, and which
//! model did it) plus session metadata.
//!
//!   claude {type:"user"|"assistant", message:{model, content:string|blocks}}
//!          blocks text, thinking, tool_use, tool_result, image; {type:"ai-title"}
//!   codex  {type:"session_meta"|"turn_context"|"response_item"|"event_msg", payload}
//!          response_item: message, reasoning, function_call(_output),
//!          custom_tool_call(_output), local_shell_call; model in turn_context
//!   pi     {type:"session"|"model_change"|"message", message:{role, content, provider, model}}
//!          roles user/assistant/toolResult; blocks text, thinking, toolCall, image

use serde::Serialize;
use serde_json::Value;

/// Tool output can run to megabytes (a base64 screenshot). The archive keeps
/// every byte; the browser view keeps this much per event.
pub const MAX_EVENT_TEXT: usize = 100_000;

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Event {
    pub seq: usize, // JSONL line number: links back to the raw line
    pub ts: String,
    pub role: String, // user, assistant, thinking, tool_call, tool_result, system, memory
    pub model: Option<String>,
    pub name: Option<String>,
    pub text: String,
    pub error: bool,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct Meta {
    pub title: Option<String>,
    pub cwd: Option<String>,
    pub models: Vec<String>, // models that actually answered, first-seen order
    pub started_at: String,
    pub ended_at: String,
    pub messages: usize,
    pub tool_calls: usize,
    pub first_prompt: String,
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn cap(text: String) -> String {
    if text.len() <= MAX_EVENT_TEXT {
        return text;
    }
    let mut end = MAX_EVENT_TEXT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n… [{} more bytes in the archive]",
        &text[..end],
        text.len() - end
    )
}

/// Text out of any content shape: string, block array, nested tool_result content.
fn flatten(content: &Value) -> String {
    match content {
        Value::String(t) => t.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .filter_map(|b| match s(&b["type"]) {
                "image" | "input_image" => Some("[image]".to_string()),
                _ if b["text"].is_string() => Some(s(&b["text"]).to_string()),
                _ if !b["content"].is_null() => Some(flatten(&b["content"])),
                _ => None,
            })
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn pretty(v: &Value) -> String {
    let v = match v {
        Value::String(t) => serde_json::from_str::<Value>(t).unwrap_or(Value::String(t.clone())),
        other => other.clone(),
    };
    match v {
        Value::String(t) => t,
        other => serde_json::to_string_pretty(&other).unwrap_or_default(),
    }
}

struct Builder {
    events: Vec<Event>,
    meta: Meta,
}

impl Builder {
    // One call per event shape across three formats; a struct argument
    // would only rename these eight fields at every call site.
    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        seq: usize,
        ts: &str,
        role: &str,
        model: Option<&str>,
        name: Option<&str>,
        text: String,
        error: bool,
    ) {
        if text.trim().is_empty() && role != "tool_call" {
            return;
        }
        self.events.push(Event {
            seq,
            ts: ts.to_string(),
            role: role.to_string(),
            model: model.filter(|m| !m.is_empty()).map(str::to_string),
            name: name.filter(|n| !n.is_empty()).map(str::to_string),
            text: cap(text),
            error,
        });
    }
    fn use_model(&mut self, m: &str) {
        if !m.is_empty() && m != "<synthetic>" && !self.meta.models.iter().any(|x| x == m) {
            self.meta.models.push(m.to_string());
        }
    }
}

pub fn parse(jsonl: &str) -> (Vec<Event>, Meta) {
    let lines: Vec<Option<Value>> = jsonl
        .split('\n')
        .map(|l| {
            if l.trim().is_empty() {
                None
            } else {
                serde_json::from_str::<Value>(l)
                    .ok()
                    .filter(Value::is_object)
            }
        })
        .collect();
    // Codex logs each turn twice (response_item and event_msg): prefer the
    // richer response_items, fall back for old logs without them.
    let codex_items = lines
        .iter()
        .flatten()
        .any(|o| s(&o["type"]) == "response_item");
    let mut b = Builder {
        events: vec![],
        meta: Meta::default(),
    };
    let mut codex_model = String::new();

    for (seq, o) in lines.iter().enumerate() {
        let Some(o) = o else { continue };
        let ts = s(&o["timestamp"]);
        if !ts.is_empty() {
            if b.meta.started_at.is_empty() || ts < b.meta.started_at.as_str() {
                b.meta.started_at = ts.to_string();
            }
            if ts > b.meta.ended_at.as_str() {
                b.meta.ended_at = ts.to_string();
            }
        }
        if b.meta.cwd.is_none() && !s(&o["cwd"]).is_empty() {
            b.meta.cwd = Some(s(&o["cwd"]).to_string());
        }
        let ty = s(&o["type"]);
        let p = &o["payload"];
        match ty {
            // ── claude ──
            "ai-title" => {
                if !s(&o["aiTitle"]).is_empty() {
                    b.meta.title = Some(s(&o["aiTitle"]).to_string());
                }
            }
            "user" | "assistant" if o["message"].is_object() => {
                let m = &o["message"];
                let model = if ty == "assistant" {
                    s(&m["model"])
                } else {
                    ""
                };
                b.use_model(model);
                let role = if o["isMeta"].as_bool() == Some(true) {
                    "system"
                } else {
                    ty
                };
                if let Value::String(t) = &m["content"] {
                    b.push(seq, ts, role, Some(model), None, t.clone(), false);
                    continue;
                }
                let mut text = vec![];
                for blk in m["content"].as_array().into_iter().flatten() {
                    match s(&blk["type"]) {
                        "text" => text.push(s(&blk["text"]).to_string()),
                        "image" => text.push("[image]".into()),
                        "thinking" => b.push(
                            seq,
                            ts,
                            "thinking",
                            Some(model),
                            None,
                            s(&blk["thinking"]).into(),
                            false,
                        ),
                        "tool_use" => b.push(
                            seq,
                            ts,
                            "tool_call",
                            Some(model),
                            Some(s(&blk["name"])),
                            pretty(&blk["input"]),
                            false,
                        ),
                        "tool_result" => b.push(
                            seq,
                            ts,
                            "tool_result",
                            None,
                            None,
                            flatten(&blk["content"]),
                            blk["is_error"].as_bool() == Some(true),
                        ),
                        _ => {}
                    }
                }
                if !text.is_empty() {
                    b.push(seq, ts, role, Some(model), None, text.join("\n"), false);
                }
            }
            "system" if o["content"].is_string() => b.push(
                seq,
                ts,
                "system",
                None,
                None,
                s(&o["content"]).into(),
                false,
            ),
            // ── codex ──
            "session_meta" => {
                if b.meta.cwd.is_none() && !s(&p["cwd"]).is_empty() {
                    b.meta.cwd = Some(s(&p["cwd"]).to_string());
                }
            }
            "turn_context" => {
                if !s(&p["model"]).is_empty() {
                    codex_model = s(&p["model"]).to_string();
                }
                if b.meta.cwd.is_none() && !s(&p["cwd"]).is_empty() {
                    b.meta.cwd = Some(s(&p["cwd"]).to_string());
                }
            }
            "response_item" => {
                let model = codex_model.clone();
                match s(&p["type"]) {
                    "message" => {
                        let role = match s(&p["role"]) {
                            "assistant" => "assistant",
                            "user" => "user",
                            _ => "system",
                        };
                        if role == "assistant" {
                            b.use_model(&model);
                        }
                        let m = (role == "assistant").then_some(model.as_str());
                        b.push(seq, ts, role, m, None, flatten(&p["content"]), false);
                    }
                    "reasoning" => b.push(
                        seq,
                        ts,
                        "thinking",
                        Some(&model),
                        None,
                        flatten(&p["summary"]),
                        false,
                    ),
                    "function_call" | "custom_tool_call" => {
                        let args = if p["arguments"].is_null() {
                            &p["input"]
                        } else {
                            &p["arguments"]
                        };
                        b.push(
                            seq,
                            ts,
                            "tool_call",
                            Some(&model),
                            Some(s(&p["name"])),
                            pretty(args),
                            false,
                        )
                    }
                    "local_shell_call" => {
                        let cmd = p["action"]["command"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .map(s)
                            .collect::<Vec<_>>()
                            .join(" ");
                        b.push(
                            seq,
                            ts,
                            "tool_call",
                            Some(&model),
                            Some("shell"),
                            cmd,
                            false,
                        )
                    }
                    "function_call_output" | "custom_tool_call_output" => {
                        let out = match &p["output"] {
                            Value::String(t) => t.clone(),
                            other => {
                                let f = flatten(&other["content"]);
                                if f.is_empty() {
                                    pretty(other)
                                } else {
                                    f
                                }
                            }
                        };
                        b.push(seq, ts, "tool_result", None, None, out, false)
                    }
                    _ => {}
                }
            }
            "event_msg" if !codex_items => match s(&p["type"]) {
                "user_message" => {
                    b.push(seq, ts, "user", None, None, s(&p["message"]).into(), false)
                }
                "agent_message" => {
                    let model = codex_model.clone();
                    b.use_model(&model);
                    b.push(
                        seq,
                        ts,
                        "assistant",
                        Some(&model),
                        None,
                        s(&p["message"]).into(),
                        false,
                    )
                }
                _ => {}
            },
            // ── pi ──
            "message" if o["message"].is_object() => {
                let m = &o["message"];
                let role = s(&m["role"]);
                let model = if role == "assistant" && !s(&m["model"]).is_empty() {
                    if s(&m["provider"]).is_empty() {
                        s(&m["model"]).to_string()
                    } else {
                        format!("{}/{}", s(&m["provider"]), s(&m["model"]))
                    }
                } else {
                    String::new()
                };
                b.use_model(&model);
                if role == "toolResult" {
                    b.push(
                        seq,
                        ts,
                        "tool_result",
                        None,
                        Some(s(&m["toolName"])),
                        flatten(&m["content"]),
                        m["isError"].as_bool() == Some(true),
                    );
                    continue;
                }
                let ev_role = match role {
                    "assistant" => "assistant",
                    "user" => "user",
                    _ => "system",
                };
                let mut text = vec![];
                if let Value::String(t) = &m["content"] {
                    text.push(t.clone());
                }
                for blk in m["content"].as_array().into_iter().flatten() {
                    match s(&blk["type"]) {
                        "text" => text.push(s(&blk["text"]).to_string()),
                        "image" => text.push("[image]".into()),
                        "thinking" => b.push(
                            seq,
                            ts,
                            "thinking",
                            Some(&model),
                            None,
                            s(&blk["thinking"]).into(),
                            false,
                        ),
                        "toolCall" => b.push(
                            seq,
                            ts,
                            "tool_call",
                            Some(&model),
                            Some(s(&blk["name"])),
                            pretty(&blk["arguments"]),
                            false,
                        ),
                        _ => {}
                    }
                }
                if !text.is_empty() {
                    b.push(seq, ts, ev_role, Some(&model), None, text.join("\n"), false);
                }
            }
            _ => {}
        }
    }

    for e in &b.events {
        if e.role == "user" || e.role == "assistant" {
            b.meta.messages += 1;
        }
        if e.role == "tool_call" {
            b.meta.tool_calls += 1;
        }
    }
    // The first thing the person typed, minus harness wrappers (system
    // reminders, image placeholders, <command-name> and friends).
    let reminder = regex::Regex::new(r"(?s)<system-reminder>.*?</system-reminder>").unwrap();
    let image = regex::Regex::new(r"(?i)\[image(?: #\d+)?\]").unwrap();
    let ws = regex::Regex::new(r"\s+").unwrap();
    b.meta.first_prompt = b
        .events
        .iter()
        .filter(|e| e.role == "user")
        .map(|e| {
            ws.replace_all(
                &image.replace_all(&reminder.replace_all(&e.text, ""), ""),
                " ",
            )
            .trim()
            .to_string()
        })
        .find(|t| !t.is_empty() && !t.starts_with('<'))
        .unwrap_or_default()
        .chars()
        .take(280)
        .collect();
    (b.events, b.meta)
}

/// A memory file is one event holding the whole note.
pub fn parse_memory(text: &str, title: &str) -> (Vec<Event>, Meta) {
    let event = Event {
        seq: 0,
        ts: String::new(),
        role: "memory".into(),
        model: None,
        name: None,
        text: cap(text.to_string()),
        error: false,
    };
    let body = text
        .strip_prefix("---\n")
        .and_then(|t| t.split_once("\n---\n").map(|(_, b)| b))
        .unwrap_or(text);
    let meta = Meta {
        title: Some(title.to_string()),
        first_prompt: body
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(280)
            .collect(),
        ..Default::default()
    };
    (vec![event], meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn j(lines: &[Value]) -> String {
        lines
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    fn roles(e: &[Event]) -> Vec<&str> {
        e.iter().map(|e| e.role.as_str()).collect()
    }

    #[test]
    fn claude_events_models_and_title() {
        let (ev, meta) = parse(&j(&[
            json!({"type":"user","cwd":"/Users/x/proj","timestamp":"2026-01-01T00:00:00Z","message":{"role":"user","content":"<command-name>/clear</command-name>"}}),
            json!({"type":"user","timestamp":"2026-01-01T00:00:01Z","message":{"role":"user","content":[{"type":"image"},{"type":"text","text":"<system-reminder>ctx</system-reminder> fix the build"}]}}),
            json!({"type":"assistant","timestamp":"2026-01-01T00:00:02Z","message":{"role":"assistant","model":"claude-opus-5-5","content":[
                {"type":"thinking","thinking":"look at the log"},{"type":"text","text":"Running it."},{"type":"tool_use","name":"Bash","input":{"command":"make"}}]}}),
            json!({"type":"user","timestamp":"2026-01-01T00:00:03Z","message":{"role":"user","content":[{"type":"tool_result","is_error":true,"content":[{"type":"text","text":"exit 2"}]}]}}),
            json!({"type":"assistant","timestamp":"2026-01-01T00:00:04Z","message":{"role":"assistant","model":"<synthetic>","content":"x"}}),
            json!({"type":"ai-title","aiTitle":"Fix the build"}),
            json!({"type":"file-history-snapshot"}),
        ]));
        assert_eq!(
            roles(&ev),
            [
                "user",
                "user",
                "thinking",
                "tool_call",
                "assistant",
                "tool_result",
                "assistant"
            ]
        );
        let tc = ev.iter().find(|e| e.role == "tool_call").unwrap();
        assert_eq!(
            (tc.name.as_deref(), tc.model.as_deref(), tc.seq),
            (Some("Bash"), Some("claude-opus-5-5"), 2)
        );
        assert!(ev.iter().find(|e| e.role == "tool_result").unwrap().error);
        assert_eq!(meta.title.as_deref(), Some("Fix the build"));
        assert_eq!(meta.cwd.as_deref(), Some("/Users/x/proj"));
        assert_eq!(meta.models, ["claude-opus-5-5"]);
        assert_eq!((meta.messages, meta.tool_calls), (4, 1));
        assert_eq!(
            (meta.started_at.as_str(), meta.ended_at.as_str()),
            ("2026-01-01T00:00:00Z", "2026-01-01T00:00:04Z")
        );
        assert_eq!(meta.first_prompt, "fix the build");
    }

    #[test]
    fn codex_prefers_response_items_and_reads_model() {
        let (ev, meta) = parse(&j(&[
            json!({"timestamp":"2026-01-01T00:00:00Z","type":"session_meta","payload":{"cwd":"/Users/x/c"}}),
            json!({"timestamp":"2026-01-01T00:00:01Z","type":"turn_context","payload":{"model":"gpt-6-sol"}}),
            json!({"timestamp":"2026-01-01T00:00:02Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"list files"}]}}),
            json!({"timestamp":"2026-01-01T00:00:02Z","type":"event_msg","payload":{"type":"user_message","message":"list files"}}),
            json!({"timestamp":"2026-01-01T00:00:03Z","type":"response_item","payload":{"type":"reasoning","summary":[{"type":"summary_text","text":"use ls"}]}}),
            json!({"timestamp":"2026-01-01T00:00:04Z","type":"response_item","payload":{"type":"function_call","name":"shell","arguments":"{\"command\":[\"ls\"]}"}}),
            json!({"timestamp":"2026-01-01T00:00:05Z","type":"response_item","payload":{"type":"function_call_output","output":"a.txt"}}),
            json!({"timestamp":"2026-01-01T00:00:06Z","type":"response_item","payload":{"type":"local_shell_call","action":{"command":["git","status"]}}}),
            json!({"timestamp":"2026-01-01T00:00:07Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"done"}]}}),
        ]));
        assert_eq!(
            roles(&ev),
            [
                "user",
                "thinking",
                "tool_call",
                "tool_result",
                "tool_call",
                "assistant"
            ]
        );
        assert_eq!(ev[2].model.as_deref(), Some("gpt-6-sol"));
        assert_eq!(ev[4].text, "git status");
        assert_eq!(meta.models, ["gpt-6-sol"]);
        assert_eq!(meta.first_prompt, "list files");
    }

    #[test]
    fn pi_models_tools_and_model_change_ignored() {
        let (ev, meta) = parse(&j(&[
            json!({"type":"session","cwd":"/Users/x/p"}),
            json!({"type":"model_change","provider":"ollama","modelId":"qwen"}),
            json!({"type":"message","timestamp":"2026-01-01T00:00:00Z","message":{"role":"user","content":[{"type":"text","text":"read it"}]}}),
            json!({"type":"message","timestamp":"2026-01-01T00:00:01Z","message":{"role":"assistant","provider":"openai-codex","model":"gpt-6-astra","content":[
                {"type":"thinking","thinking":"ok"},{"type":"toolCall","name":"read","arguments":{"path":"a.md"}}]}}),
            json!({"type":"message","timestamp":"2026-01-01T00:00:02Z","message":{"role":"toolResult","toolName":"read","isError":false,"content":[{"type":"text","text":"# A"}]}}),
        ]));
        assert_eq!(roles(&ev), ["user", "thinking", "tool_call", "tool_result"]);
        assert_eq!(ev[2].model.as_deref(), Some("openai-codex/gpt-6-astra"));
        assert_eq!(meta.models, ["openai-codex/gpt-6-astra"]);
    }

    #[test]
    fn huge_output_capped_and_garbage_skipped() {
        let (ev, _) = parse(&j(&[
            json!({"type":"user","message":{"role":"user","content":[{"type":"tool_result","content":"x".repeat(MAX_EVENT_TEXT + 500)}]}}),
        ]));
        assert!(ev[0].text.contains("500 more bytes in the archive"));
        assert!(parse("not json\n{\"type\":\n\n").0.is_empty());
    }
}
