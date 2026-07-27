//! A small, strict TOML parser.
//!
//! Only the subset the manifest schema uses: tables, dotted table headers,
//! string/integer/boolean values, and arrays of strings. Everything else is a
//! parse error rather than a best-effort interpretation.
//!
//! Strictness is the point. This file decides what gets installed on the
//! system, so silently accepting something we do not understand — an inline
//! table, a datetime, a float — and then ignoring it would mean a user's
//! manifest says one thing and the machine does another. A rejected manifest is
//! a bad afternoon; a silently misread one is a machine that is not what its
//! manifest claims, which is the single promise this project makes about
//! configuration.

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Integer(i64),
    Boolean(bool),
    Array(Vec<Value>),
    Table(Table),
}

pub type Table = BTreeMap<String, Value>;

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_table(&self) -> Option<&Table> {
        match self {
            Value::Table(t) => Some(t),
            _ => None,
        }
    }

    /// Array of strings. Returns `None` if any element is not a string, rather
    /// than silently dropping it — a package list that quietly loses an entry
    /// is exactly the failure this parser exists to prevent.
    pub fn as_str_array(&self) -> Option<Vec<String>> {
        match self {
            Value::Array(items) => items
                .iter()
                .map(|v| v.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>(),
            _ => None,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Value::String(_) => "string",
            Value::Integer(_) => "integer",
            Value::Boolean(_) => "boolean",
            Value::Array(_) => "array",
            Value::Table(_) => "table",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

pub fn parse(input: &str) -> Result<Table, ParseError> {
    Parser::new(input).parse()
}

struct Parser<'a> {
    lines: Vec<&'a str>,
    line_no: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Parser {
            lines: input.lines().collect(),
            line_no: 0,
        }
    }

    fn err<T>(&self, message: impl Into<String>) -> Result<T, ParseError> {
        Err(ParseError {
            line: self.line_no,
            message: message.into(),
        })
    }

    fn parse(mut self) -> Result<Table, ParseError> {
        let mut root = Table::new();
        // The table the next key/value pair belongs to, as a path from the root.
        let mut current: Vec<String> = Vec::new();
        // Every header seen, so a duplicate is an error rather than a silent
        // merge that loses whichever definition came first.
        let mut seen_headers: Vec<Vec<String>> = Vec::new();

        let mut idx = 0;
        while idx < self.lines.len() {
            self.line_no = idx + 1;
            let raw = self.lines[idx];
            idx += 1;

            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }

            if let Some(header) = line.strip_prefix('[') {
                if header.starts_with('[') {
                    return self.err("arrays of tables are not supported in the manifest schema");
                }
                let header = match header.strip_suffix(']') {
                    Some(h) => h.trim(),
                    None => return self.err("unterminated table header"),
                };
                let path = parse_key_path(header);
                if path.is_empty() || path.iter().any(|p| p.is_empty()) {
                    return self.err(format!("malformed table header: [{header}]"));
                }
                if seen_headers.contains(&path) {
                    return self.err(format!("duplicate table [{}]", path.join(".")));
                }
                seen_headers.push(path.clone());
                ensure_table(&mut root, &path).map_err(|m| ParseError {
                    line: self.line_no,
                    message: m,
                })?;
                current = path;
                continue;
            }

            let (key, rest) = match line.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => return self.err(format!("expected 'key = value', found: {line}")),
            };
            if key.is_empty() {
                return self.err("empty key");
            }

            // An array may span lines. Gather until the brackets balance.
            let mut value_text = rest.to_string();
            if rest.starts_with('[') && !brackets_balanced(rest) {
                while idx < self.lines.len() && !brackets_balanced(&value_text) {
                    self.line_no = idx + 1;
                    value_text.push(' ');
                    value_text.push_str(strip_comment(self.lines[idx]).trim());
                    idx += 1;
                }
                if !brackets_balanced(&value_text) {
                    return self.err("unterminated array");
                }
            }

            let value = self.parse_value(&value_text)?;
            let key_path = parse_key_path(key);
            let mut full = current.clone();
            full.extend(key_path);

            insert(&mut root, &full, value).map_err(|m| ParseError {
                line: self.line_no,
                message: m,
            })?;
        }

        Ok(root)
    }

    fn parse_value(&self, text: &str) -> Result<Value, ParseError> {
        let text = text.trim();
        if text.is_empty() {
            return self.err("missing value");
        }

        if let Some(body) = text.strip_prefix('[') {
            let body = match body.strip_suffix(']') {
                Some(b) => b,
                None => return self.err("unterminated array"),
            };
            let mut items = Vec::new();
            for element in split_top_level(body) {
                let element = element.trim();
                if element.is_empty() {
                    continue;
                }
                items.push(self.parse_value(element)?);
            }
            return Ok(Value::Array(items));
        }

        if text.starts_with('"') || text.starts_with('\'') {
            return self.parse_string(text);
        }

        match text {
            "true" => return Ok(Value::Boolean(true)),
            "false" => return Ok(Value::Boolean(false)),
            _ => {}
        }

        // Integers, with TOML's underscore separators.
        let cleaned = text.replace('_', "");
        if let Ok(n) = cleaned.parse::<i64>() {
            return Ok(Value::Integer(n));
        }

        // Deliberately not supported: floats, datetimes, inline tables. Say so
        // rather than guessing — the caller is defining a system.
        if text.starts_with('{') {
            return self.err("inline tables are not supported in the manifest schema");
        }
        self.err(format!(
            "unrecognised value: {text}\n         \
             the manifest schema supports strings, integers, booleans, and arrays"
        ))
    }

    fn parse_string(&self, text: &str) -> Result<Value, ParseError> {
        let quote = text.chars().next().unwrap();
        let body = &text[1..];
        let Some(end) = find_closing_quote(body, quote) else {
            return self.err("unterminated string");
        };
        let content = &body[..end];
        let trailing = body[end + 1..].trim();
        if !trailing.is_empty() {
            return self.err(format!("trailing characters after string: {trailing}"));
        }

        if quote == '\'' {
            // Literal string: no escape processing, by TOML's definition.
            return Ok(Value::String(content.to_string()));
        }

        let mut out = String::with_capacity(content.len());
        let mut chars = content.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                        Some(c) => out.push(c),
                        None => return self.err(format!("invalid \\u escape: \\u{hex}")),
                    }
                }
                Some(other) => return self.err(format!("unknown escape: \\{other}")),
                None => return self.err("string ends with a backslash"),
            }
        }
        Ok(Value::String(out))
    }
}

fn strip_comment(line: &str) -> &str {
    // A '#' inside a string is not a comment. Track quoting rather than
    // splitting naively, or a package named "foo#bar" truncates the line.
    let bytes = line.as_bytes();
    let mut in_string: Option<u8> = None;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate() {
        match in_string {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if b == b'\\' && q == b'"' {
                    escaped = true;
                } else if b == q {
                    in_string = None;
                }
            }
            None => {
                if b == b'"' || b == b'\'' {
                    in_string = Some(b);
                } else if b == b'#' {
                    return &line[..i];
                }
            }
        }
    }
    line
}

fn find_closing_quote(s: &str, quote: char) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' && quote == '"' {
            escaped = true;
        } else if c == quote {
            return Some(i);
        }
    }
    None
}

/// Split on commas that are not inside a string or a nested array.
fn split_top_level(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut in_string: Option<char> = None;
    let mut escaped = false;
    let mut current = String::new();

    for c in s.chars() {
        match in_string {
            Some(q) => {
                current.push(c);
                if escaped {
                    escaped = false;
                } else if c == '\\' && q == '"' {
                    escaped = true;
                } else if c == q {
                    in_string = None;
                }
            }
            None => match c {
                '"' | '\'' => {
                    in_string = Some(c);
                    current.push(c);
                }
                '[' => {
                    depth += 1;
                    current.push(c);
                }
                ']' => {
                    depth = depth.saturating_sub(1);
                    current.push(c);
                }
                ',' if depth == 0 => {
                    out.push(std::mem::take(&mut current));
                }
                _ => current.push(c),
            },
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

fn brackets_balanced(s: &str) -> bool {
    let mut depth = 0i32;
    let mut in_string: Option<char> = None;
    let mut escaped = false;
    for c in s.chars() {
        match in_string {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' && q == '"' {
                    escaped = true;
                } else if c == q {
                    in_string = None;
                }
            }
            None => match c {
                '"' | '\'' => in_string = Some(c),
                '[' => depth += 1,
                ']' => depth -= 1,
                _ => {}
            },
        }
    }
    depth == 0
}

/// Split a dotted key, honouring quoted segments so a user name containing a
/// dot does not silently become two levels of table.
fn parse_key_path(key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_string: Option<char> = None;

    for c in key.chars() {
        match in_string {
            Some(q) if c == q => in_string = None,
            Some(_) => current.push(c),
            None => match c {
                '"' | '\'' => in_string = Some(c),
                '.' => out.push(std::mem::take(&mut current).trim().to_string()),
                _ => current.push(c),
            },
        }
    }
    out.push(current.trim().to_string());
    out
}

fn ensure_table(root: &mut Table, path: &[String]) -> Result<(), String> {
    let mut node = root;
    for (i, segment) in path.iter().enumerate() {
        let entry = node
            .entry(segment.clone())
            .or_insert_with(|| Value::Table(Table::new()));
        node = match entry {
            Value::Table(t) => t,
            other => {
                return Err(format!(
                    "{} is a {}, but [{}] treats it as a table",
                    path[..=i].join("."),
                    other.type_name(),
                    path.join(".")
                ))
            }
        };
    }
    Ok(())
}

fn insert(root: &mut Table, path: &[String], value: Value) -> Result<(), String> {
    let (last, parents) = path.split_last().expect("path is never empty");
    ensure_table(root, parents)?;
    let mut node = root;
    for segment in parents {
        node = match node.get_mut(segment) {
            Some(Value::Table(t)) => t,
            _ => unreachable!("ensure_table just created this"),
        };
    }
    if node.contains_key(last) {
        return Err(format!("duplicate key: {}", path.join(".")));
    }
    node.insert(last.clone(), value);
    Ok(())
}

/// Look up a dotted path in a parsed table.
pub fn get<'a>(table: &'a Table, path: &str) -> Option<&'a Value> {
    let mut node = table;
    let segments: Vec<&str> = path.split('.').collect();
    let (last, parents) = segments.split_last()?;
    for segment in parents {
        node = node.get(*segment)?.as_table()?;
    }
    node.get(*last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_default_manifest_shape() {
        let src = r#"
[system]
channel   = "stable"
snapshot  = "2026-07-20"
hardening = "balanced"

[packages]
system = ["firefox", "neovim", "git"]

[backup]
enabled = true
retention = "7d 4w 6m"
"#;
        let t = parse(src).unwrap();
        assert_eq!(get(&t, "system.channel").unwrap().as_str(), Some("stable"));
        assert_eq!(
            get(&t, "packages.system").unwrap().as_str_array().unwrap(),
            vec!["firefox", "neovim", "git"]
        );
        assert_eq!(get(&t, "backup.enabled").unwrap().as_bool(), Some(true));
    }

    #[test]
    fn handles_multiline_arrays_with_trailing_commas_and_comments() {
        let src = r#"
[packages]
system = [
  "firefox",       # the browser
  "neovim",
  "git",           # trailing comma below is legal TOML
]
"#;
        let t = parse(src).unwrap();
        assert_eq!(
            get(&t, "packages.system").unwrap().as_str_array().unwrap(),
            vec!["firefox", "neovim", "git"]
        );
    }

    #[test]
    fn a_hash_inside_a_string_is_not_a_comment() {
        // Truncating here would silently drop half a package name.
        let src = r#"
[packages]
system = ["foo#bar", "baz"]
name = "a # b"
"#;
        let t = parse(src).unwrap();
        assert_eq!(
            get(&t, "packages.system").unwrap().as_str_array().unwrap(),
            vec!["foo#bar", "baz"]
        );
        assert_eq!(get(&t, "packages.name").unwrap().as_str(), Some("a # b"));
    }

    #[test]
    fn nested_table_headers() {
        let src = r#"
[users.chase]
storage = "luks"

[users.work]
storage = "luks"
sandbox = "strict"
"#;
        let t = parse(src).unwrap();
        assert_eq!(
            get(&t, "users.chase.storage").unwrap().as_str(),
            Some("luks")
        );
        assert_eq!(
            get(&t, "users.work.sandbox").unwrap().as_str(),
            Some("strict")
        );
    }

    #[test]
    fn duplicate_keys_and_tables_are_errors_not_silent_merges() {
        // A manifest whose second definition silently wins is a machine that is
        // not what its author thinks it is.
        assert!(parse("[a]\nx = 1\nx = 2\n").is_err());
        assert!(parse("[a]\nx = 1\n\n[a]\ny = 2\n").is_err());
    }

    #[test]
    fn rejects_constructs_it_does_not_implement() {
        // Silently ignoring an inline table would mean the manifest says one
        // thing and the machine does another.
        assert!(parse("[a]\nx = { y = 1 }\n").is_err());
        assert!(parse("[[a]]\nx = 1\n").is_err());
        assert!(parse("[a]\nx = 1.5\n").is_err());
        assert!(parse("[a]\nx = 2026-07-20T00:00:00Z\n").is_err());
    }

    #[test]
    fn rejects_malformed_input_with_a_line_number() {
        let e = parse("[system]\nchannel = \n").unwrap_err();
        assert_eq!(e.line, 2);
        let e = parse("[unterminated\n").unwrap_err();
        assert_eq!(e.line, 1);
        let e = parse("[a]\nno equals sign here\n").unwrap_err();
        assert_eq!(e.line, 2);
    }

    #[test]
    fn string_escapes() {
        let t = parse(
            r#"[a]
b = "line\nbreak"
c = "quote\"inside"
d = 'literal\nnot escaped'
e = "A"
"#,
        )
        .unwrap();
        assert_eq!(get(&t, "a.b").unwrap().as_str(), Some("line\nbreak"));
        assert_eq!(get(&t, "a.c").unwrap().as_str(), Some("quote\"inside"));
        assert_eq!(
            get(&t, "a.d").unwrap().as_str(),
            Some(r"literal\nnot escaped")
        );
        assert_eq!(get(&t, "a.e").unwrap().as_str(), Some("A"));
    }

    #[test]
    fn an_array_with_a_non_string_element_fails_rather_than_dropping_it() {
        let t = parse("[a]\nb = [\"x\", 1, \"y\"]\n").unwrap();
        assert!(get(&t, "a.b").unwrap().as_str_array().is_none());
    }

    #[test]
    fn quoted_key_segments_are_not_split_on_dots() {
        let t = parse("[users]\n\"user.name\" = \"value\"\n").unwrap();
        assert_eq!(get(&t, "users.user.name"), None);
        let users = get(&t, "users").unwrap().as_table().unwrap();
        assert_eq!(users.get("user.name").unwrap().as_str(), Some("value"));
    }

    #[test]
    fn dotted_keys_inside_a_table() {
        let t = parse("[system]\nnested.key = \"v\"\n").unwrap();
        assert_eq!(get(&t, "system.nested.key").unwrap().as_str(), Some("v"));
    }

    #[test]
    fn empty_input_is_an_empty_table_not_an_error() {
        assert_eq!(parse("").unwrap().len(), 0);
        assert_eq!(parse("# just a comment\n").unwrap().len(), 0);
    }

    #[test]
    fn key_defined_as_value_then_used_as_table_is_an_error() {
        assert!(parse("[a]\nb = \"x\"\n\n[a.b]\nc = 1\n").is_err());
    }

    /// The manifest that ships with the repo must parse. If it does not, the
    /// example we hand people is broken.
    #[test]
    fn the_shipped_default_manifest_parses() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("image/manifest.default.toml");
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let t = parse(&body).unwrap_or_else(|e| panic!("default manifest does not parse: {e}"));
        assert!(get(&t, "system.snapshot").is_some());
    }
}
