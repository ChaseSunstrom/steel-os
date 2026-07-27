//! Minimal JSON writer.
//!
//! `steel-check --json` is a stable, machine-readable contract shared by CI and
//! by users, so the encoder needs to be correct about escaping and about key
//! ordering (see `Value::Object`, which preserves insertion order so output is
//! byte-stable across runs). It does not need to be general, and it never
//! parses, so this is a writer only.

use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Int(i64),
    Str(String),
    Array(Vec<Value>),
    /// Insertion-ordered. Never sorted: field order is part of the stable
    /// output contract, and re-ordering would break byte-for-byte comparison.
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }

    pub fn array<I: IntoIterator<Item = Value>>(items: I) -> Value {
        Value::Array(items.into_iter().collect())
    }

    pub fn object<I, K>(fields: I) -> Value
    where
        I: IntoIterator<Item = (K, Value)>,
        K: Into<String>,
    {
        Value::Object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// Pretty-print with two-space indentation and a trailing newline.
    pub fn to_pretty_string(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out.push('\n');
        out
    }

    fn write(&self, out: &mut String, indent: usize) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Int(n) => {
                let _ = write!(out, "{n}");
            }
            Value::Str(s) => write_escaped(out, s),
            Value::Array(items) if items.is_empty() => out.push_str("[]"),
            Value::Array(items) => {
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    pad(out, indent + 1);
                    item.write(out, indent + 1);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                pad(out, indent);
                out.push(']');
            }
            Value::Object(fields) if fields.is_empty() => out.push_str("{}"),
            Value::Object(fields) => {
                out.push_str("{\n");
                for (i, (key, value)) in fields.iter().enumerate() {
                    pad(out, indent + 1);
                    write_escaped(out, key);
                    out.push_str(": ");
                    value.write(out, indent + 1);
                    if i + 1 < fields.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                pad(out, indent);
                out.push('}');
            }
        }
    }
}

fn pad(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

fn write_escaped(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            // Control characters and DEL. Everything else goes out as UTF-8:
            // check details can contain non-ASCII (device names, paths).
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_and_quote_characters() {
        // \u0001 and \u007f must come out as escapes, not as raw bytes: check
        // details can carry control characters from device names and command
        // output, and a raw DEL in the JSON breaks every consumer downstream.
        let v = Value::str("a\"b\\c\nd\te\u{1}f\u{7f}");
        assert_eq!(
            v.to_pretty_string().trim_end(),
            r#""a\"b\\c\nd\te\u0001f\u007f""#
        );
    }

    #[test]
    fn passes_utf8_through_unescaped() {
        let v = Value::str("café — ünïcode");
        assert_eq!(v.to_pretty_string().trim_end(), "\"café — ünïcode\"");
    }

    #[test]
    fn preserves_object_key_order() {
        let v = Value::object([
            ("zebra", Value::Int(1)),
            ("apple", Value::Int(2)),
            ("moose", Value::Int(3)),
        ]);
        let s = v.to_pretty_string();
        let zebra = s.find("zebra").unwrap();
        let apple = s.find("apple").unwrap();
        let moose = s.find("moose").unwrap();
        assert!(
            zebra < apple && apple < moose,
            "key order not preserved: {s}"
        );
    }

    #[test]
    fn renders_empty_containers_inline() {
        assert_eq!(Value::Array(vec![]).to_pretty_string(), "[]\n");
        assert_eq!(Value::Object(vec![]).to_pretty_string(), "{}\n");
    }

    #[test]
    fn nests_with_two_space_indentation() {
        let v = Value::object([("a", Value::array([Value::Int(1), Value::Int(2)]))]);
        assert_eq!(
            v.to_pretty_string(),
            "{\n  \"a\": [\n    1,\n    2\n  ]\n}\n"
        );
    }
}
