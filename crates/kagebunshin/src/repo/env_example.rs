//! Reading key names out of a `.env.example`, and, for onboarding only,
//! keys and values out of a real `.env`.
//!
//! [`parse`] gives names, and the values that are not empty only so that
//! `diff` can suggest one as a plain setting. Quoted values that run over
//! several lines are read whole, so a line inside a value never turns into a key. Bad
//! lines are reported by number and kind, never by content: an example file
//! is sometimes a copy of a real `.env`.
//!
//! The syntax is the common dotenv subset:
//!
//! ```text
//! # comment
//! KEY=value                 unquoted values end at the end of the line
//! export KEY=value          `export ` is ignored
//! KEY = "a \" b"            double quotes, with backslash escapes
//! KEY='raw'                 single quotes and backticks, no escapes
//! KEY="line one
//! line two"                 quoted values may span lines
//! ```
//!
//! A UTF-8 byte order mark at the start and `\r\n` line endings are accepted.
//! A line without `=` is a bad line, not a key: a line of an unquoted
//! multi-line value (a PEM body, say) can look exactly like a key name.

use std::fmt;

use crate::secret::SecretValue;
use crate::types::KeyName;

/// The keys of one file, and the lines that could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvExample {
    /// In file order. A key declared twice appears once, where it first
    /// appeared.
    pub keys: Vec<KeyName>,
    /// The values that are not empty, the last one for a key set twice.
    pub values: ExampleValues,
    pub bad_lines: Vec<BadLine>,
}

/// `.env.example`'s values that are not empty and fit on one line. Often
/// placeholders, and in a copy of a real `.env` secrets: shown only as a
/// suggested plain setting that a person or agent judges, never in `Debug`.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct ExampleValues(std::collections::BTreeMap<KeyName, String>);

impl ExampleValues {
    pub fn get(&self, key: &KeyName) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// The keys that have a value, in name order.
    pub fn keys(&self) -> impl Iterator<Item = &KeyName> {
        self.0.keys()
    }
}

impl fmt::Debug for ExampleValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExampleValues(<{} redacted>)", self.0.len())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct BadLine {
    /// 1-based.
    pub line: usize,
    pub problem: LineProblem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LineProblem {
    /// The line has no `=`, or the text before it is not a valid
    /// environment variable name.
    BadKey,
    /// A quoted value is never closed. Everything after it is skipped, since
    /// it may all be part of the value.
    UnterminatedQuote,
}

impl fmt::Display for BadLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.problem {
            LineProblem::BadKey => "is not a KEY=value line with a valid key name",
            LineProblem::UnterminatedQuote => {
                "starts a quoted value that is never closed; the rest of the file was skipped"
            }
        };
        write!(f, "line {} {what}", self.line)
    }
}

pub fn parse(text: &str) -> EnvExample {
    let mut values = Vec::new();
    let mut parsed = walk(text, Some(&mut values));
    parsed.values = ExampleValues(
        values
            .into_iter()
            .filter(|(_, v)| !v.is_empty() && !v.expose().contains(['\n', '\r']))
            .map(|(k, v)| (k, v.expose().to_owned()))
            .collect(),
    );
    parsed
}

/// The keys and values of a real `.env`, in file order, and the lines that
/// could not be read. A key set twice keeps its last value, as dotenv
/// loaders do. Values are taken literally, with no `${VAR}` expansion: an
/// unquoted value ends at a `#` after a space or tab and is trimmed; in
/// double quotes `\n`, `\r`, `\t`, `\\`, `\"` and `\$` are unescaped, and
/// any other backslash is kept.
pub fn parse_values(text: &str) -> (Vec<(KeyName, SecretValue)>, Vec<BadLine>) {
    let mut values = Vec::new();
    let parsed = walk(text, Some(&mut values));
    (values, parsed.bad_lines)
}

fn walk(text: &str, mut values: Option<&mut Vec<(KeyName, SecretValue)>>) -> EnvExample {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out = EnvExample::default();
    let mut lines = text
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .enumerate()
        .map(|(i, l)| (i + 1, l));

    while let Some((number, line)) = lines.next() {
        let line = line.trim_start_matches([' ', '\t']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = strip_export(line).split_once('=') else {
            out.bad_lines.push(BadLine {
                line: number,
                problem: LineProblem::BadKey,
            });
            continue;
        };
        // Skip the value whatever the key: a bad key must not stop a
        // multi-line value from being skipped.
        let mut read = values
            .is_some()
            .then(|| zeroize::Zeroizing::new(String::new()));
        let closed = skip_value(value, &mut lines, read.as_deref_mut());
        match name.trim_matches([' ', '\t']).parse::<KeyName>() {
            Ok(key) => {
                if let (Some(values), Some(mut read), true) = (values.as_deref_mut(), read, closed)
                {
                    values.retain(|(k, _)| *k != key);
                    values.push((key.clone(), SecretValue::new(std::mem::take(&mut *read))));
                }
                if !out.keys.contains(&key) {
                    out.keys.push(key);
                }
            }
            Err(_) => out.bad_lines.push(BadLine {
                line: number,
                problem: LineProblem::BadKey,
            }),
        }
        if !closed {
            out.bad_lines.push(BadLine {
                line: number,
                problem: LineProblem::UnterminatedQuote,
            });
            break;
        }
    }
    out
}

fn strip_export(line: &str) -> &str {
    match line.strip_prefix("export") {
        Some(rest) if rest.starts_with([' ', '\t']) => rest.trim_start_matches([' ', '\t']),
        _ => line,
    }
}

/// Consumes a value that starts on the current line, and any further lines a
/// quoted value spans, writing it to `out` if given. Returns false if a
/// quote is never closed.
fn skip_value<'a>(
    raw: &str,
    lines: &mut impl Iterator<Item = (usize, &'a str)>,
    mut out: Option<&mut String>,
) -> bool {
    let value = raw.trim_start_matches([' ', '\t']);
    let Some(quote) = value
        .chars()
        .next()
        .filter(|c| matches!(c, '"' | '\'' | '`'))
    else {
        if let Some(out) = out {
            let end = raw
                .match_indices('#')
                .find(|(i, _)| raw[..*i].ends_with([' ', '\t']))
                .map_or(raw.len(), |(i, _)| i);
            out.push_str(raw[..end].trim_matches([' ', '\t']));
        }
        return true;
    };
    let mut rest = &value[1..];
    let mut escaped = false;
    loop {
        for c in rest.chars() {
            if escaped {
                escaped = false;
                if let Some(out) = out.as_deref_mut() {
                    match c {
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        '\\' | '"' | '$' => out.push(c),
                        _ => {
                            out.push('\\');
                            out.push(c);
                        }
                    }
                }
            } else if c == '\\' && quote == '"' {
                escaped = true;
            } else if c == quote {
                // Anything after the closing quote is ignored.
                return true;
            } else if let Some(out) = out.as_deref_mut() {
                out.push(c);
            }
        }
        // The newline itself is part of the value; an escape before it
        // escapes nothing that matters here.
        if let Some(out) = out.as_deref_mut() {
            if escaped {
                out.push('\\');
            }
            out.push('\n');
        }
        escaped = false;
        match lines.next() {
            Some((_, next)) => rest = next,
            None => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::test_support::{Canary, assert_no_canary};

    fn keys(text: &str) -> Vec<String> {
        let parsed = parse(text);
        assert_eq!(parsed.bad_lines, [], "{text:?}");
        parsed.keys.iter().map(|k| k.to_string()).collect()
    }

    #[test]
    fn basic_forms() {
        let text = "\
# A comment
   # an indented comment

DATABASE_URL=postgres://localhost/dev
export API_KEY=abc
export\tTABBED=1
SPACED = value with spaces
EMPTY=
  INDENTED=1
DOUBLE=\"a \\\" b # not a comment\"
SINGLE='it''s'
TICK=`x`
COMMENTED=value # trailing comment
DATABASE_URL=duplicate
exported=1
export=1
";
        assert_eq!(
            keys(text),
            [
                "DATABASE_URL",
                "API_KEY",
                "TABBED",
                "SPACED",
                "EMPTY",
                "INDENTED",
                "DOUBLE",
                "SINGLE",
                "TICK",
                "COMMENTED",
                "exported",
                "export",
            ]
        );
    }

    #[test]
    fn multi_line_values_do_not_produce_keys() {
        let canary = Canary::new();
        let c = canary.value();
        let text = format!(
            "\
FIRST=1
PRIVATE_KEY=\"-----BEGIN KEY-----
INSIDE_DOUBLE={c}
export ALSO_INSIDE=1
# not a comment either
\\\"STILL_INSIDE=1
-----END KEY-----\"
MIDDLE=2
SINGLE='line one
INSIDE_SINGLE={c}
it ends here'
TICKED=`one
INSIDE_TICK={c}
`
LAST=3
"
        );
        let got = keys(&text);
        assert_eq!(
            got,
            ["FIRST", "PRIVATE_KEY", "MIDDLE", "SINGLE", "TICKED", "LAST"]
        );
        assert_no_canary(&canary, &format!("{:?}", parse(&text)));
    }

    #[test]
    fn single_quotes_have_no_escapes() {
        // The backslash does not escape the closing quote, so NEXT is a key.
        assert_eq!(keys("A='x\\'\nNEXT=1\n"), ["A", "NEXT"]);
        // In double quotes it does, so NEXT is inside the value.
        assert_eq!(keys("A=\"x\\\"\nNEXT=1\n\"\nB=1"), ["A", "B"]);
        // An escaped backslash before the quote closes it.
        assert_eq!(keys("A=\"x\\\\\"\nNEXT=1\n"), ["A", "NEXT"]);
    }

    #[test]
    fn crlf_and_bom() {
        assert_eq!(
            keys("\u{feff}FIRST=1\r\nexport SECOND=\"a\r\nINSIDE=1\r\n\"\r\nTHIRD=3\r\n"),
            ["FIRST", "SECOND", "THIRD"]
        );
        // A BOM anywhere else is not stripped.
        let parsed = parse("A=1\n\u{feff}B=2\n");
        assert_eq!(
            parsed.bad_lines,
            [BadLine {
                line: 2,
                problem: LineProblem::BadKey
            }]
        );
    }

    #[test]
    fn an_example_keeps_its_values_that_are_not_empty() {
        let got = parse("PORT=3000\nSECRET=\nNAME='a b'\nPORT=8080\nPEM=\"one\ntwo\"\n").values;
        let get = |k: &str| got.get(&k.parse().unwrap());
        assert_eq!(get("NAME"), Some("a b"));
        assert_eq!(get("PORT"), Some("8080"));
        // Empty, and over several lines (a key, a certificate): left out.
        assert_eq!((get("SECRET"), get("PEM")), (None, None));
        assert_eq!(format!("{got:?}"), "ExampleValues(<2 redacted>)");
    }

    #[test]
    fn values_of_a_real_env() {
        let text = [
            "# comment",
            "PLAIN=a b \t",
            "export EXPORTED=1",
            "COMMENTED=value # comment",
            "HASH=a#b",
            "EMPTY=",
            "SPACED = padded",
            r#"DOUBLE="a \" \\ \n \$ \x # kept" # comment"#,
            r"SINGLE='raw \n'",
            "TICK=`t`",
            "MULTI=\"line one\r",
            "line two\"",
            "DUP=first",
            "DUP=second",
        ]
        .join("\n");
        let (values, bad) = parse_values(&text);
        assert_eq!(bad, []);
        let got: Vec<(&str, &str)> = values
            .iter()
            .map(|(k, v)| (k.as_str(), v.expose()))
            .collect();
        assert_eq!(
            got,
            [
                ("PLAIN", "a b"),
                ("EXPORTED", "1"),
                ("COMMENTED", "value"),
                ("HASH", "a#b"),
                ("EMPTY", ""),
                ("SPACED", "padded"),
                ("DOUBLE", "a \" \\ \n $ \\x # kept"),
                ("SINGLE", r"raw \n"),
                ("TICK", "t"),
                ("MULTI", "line one\nline two"),
                ("DUP", "second"),
            ]
        );
        let canary = Canary::new();
        let parsed = parse_values(&format!("A={}\nB=\"{}\"\n", canary.value(), canary.value()));
        assert_no_canary(&canary, &format!("{parsed:?}"));
    }

    #[test]
    fn bad_lines_are_reported_by_number_only() {
        let canary = Canary::new();
        let c = canary.value();
        let text = format!(
            "GOOD=1\n{c}\nnot a key={c}\n1BAD=x\nexport\nBAD-NAME=\"multi\nHIDDEN=1\n\"\nAFTER=1\nOPEN=\"{c}\nNEVER=1\n"
        );
        let parsed = parse(&text);
        let names: Vec<_> = parsed.keys.iter().map(|k| k.as_str()).collect();
        // The key of an unterminated value still counts.
        assert_eq!(names, ["GOOD", "AFTER", "OPEN"]);
        let lines: Vec<_> = parsed
            .bad_lines
            .iter()
            .map(|b| (b.line, b.problem))
            .collect();
        assert_eq!(
            lines,
            [
                (2, LineProblem::BadKey),
                (3, LineProblem::BadKey),
                (4, LineProblem::BadKey),
                (5, LineProblem::BadKey),
                (6, LineProblem::BadKey),
                (10, LineProblem::UnterminatedQuote),
            ]
        );
        let shown: Vec<String> = parsed.bad_lines.iter().map(ToString::to_string).collect();
        assert_eq!(
            shown[0],
            "line 2 is not a KEY=value line with a valid key name"
        );
        for s in &shown {
            assert_no_canary(&canary, s);
        }
        assert_no_canary(&canary, &format!("{parsed:?}"));
    }

    /// How a generated value is written.
    #[derive(Debug, Clone)]
    enum Quoting {
        None,
        Double,
        Single,
        Backtick,
    }

    /// A value made of lines that look like assignments of names in the
    /// `V_` namespace, which no generated key uses, mixed with quote and
    /// comment characters.
    fn value_strategy() -> impl Strategy<Value = (Quoting, String)> {
        let line = prop_oneof![
            "V_[A-Z0-9_]{0,8}=[a-z0-9]{0,6}",
            "export V_[A-Z]{1,6}=1",
            "V_[A-Z]{1,6}",
            "[A-Za-z0-9]{1,16}",
            "# V_[A-Z]{1,6}=1",
            "[a-z0-9 #=\\\\\"'`]{0,12}",
        ];
        (
            prop_oneof![
                Just(Quoting::None),
                Just(Quoting::Double),
                Just(Quoting::Single),
                Just(Quoting::Backtick),
            ],
            prop::collection::vec(line, 1..5),
        )
            .prop_map(|(q, lines)| {
                let value = match q {
                    // Unquoted values are one line and must not start with a
                    // quote.
                    Quoting::None => lines[0]
                        .trim_start_matches(['"', '\'', '`', ' '])
                        .to_owned(),
                    Quoting::Double => lines.join("\n"),
                    Quoting::Single => lines.join("\n").replace('\'', ""),
                    Quoting::Backtick => lines.join("\n").replace('`', ""),
                };
                (q, value)
            })
    }

    fn write(key: &str, export: bool, crlf: bool, (q, v): &(Quoting, String)) -> String {
        let body = match q {
            Quoting::None => v.clone(),
            Quoting::Double => format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\"")),
            Quoting::Single => format!("'{v}'"),
            Quoting::Backtick => format!("`{v}`"),
        };
        let line = format!("{}{key}={body}\n", if export { "export " } else { "" });
        if crlf {
            line.replace('\n', "\r\n")
        } else {
            line
        }
    }

    proptest! {
        #[test]
        fn names_never_come_from_values(
            entries in prop::collection::vec(
                ("K_[A-Z0-9_]{0,10}", any::<bool>(), value_strategy()),
                0..12,
            ),
            crlf in any::<bool>(),
            bom in any::<bool>(),
        ) {
            let mut text = String::from(if bom { "\u{feff}" } else { "" });
            let mut want: Vec<String> = Vec::new();
            for (key, export, value) in &entries {
                text.push_str(&write(key, *export, crlf, value));
                if !want.contains(key) {
                    want.push(key.clone());
                }
            }
            let parsed = parse(&text);
            prop_assert_eq!(&parsed.bad_lines, &Vec::<BadLine>::new());
            let got: Vec<String> = parsed.keys.iter().map(|k| k.to_string()).collect();
            prop_assert!(got.iter().all(|k| !k.starts_with("V_")), "{got:?}");
            prop_assert_eq!(got, want);

            // Quoted values come back as written; the last of a key wins.
            let mut want: Vec<(String, Option<String>)> = Vec::new();
            for (key, _, (q, v)) in &entries {
                want.retain(|(k, _)| k != key);
                want.push((key.clone(), (!matches!(q, Quoting::None)).then(|| v.clone())));
            }
            let (values, bad) = parse_values(&text);
            prop_assert_eq!(bad, Vec::<BadLine>::new());
            prop_assert_eq!(values.len(), want.len());
            for ((k, v), (want_k, want_v)) in values.iter().zip(&want) {
                prop_assert_eq!(k.as_str(), want_k);
                if let Some(want_v) = want_v {
                    prop_assert_eq!(v.expose(), want_v);
                }
            }
        }

        #[test]
        fn never_panics(text in "[A-Za-z0-9_ =#\"'`\\\\\r\n\u{feff}]{0,200}") {
            let parsed = parse(&text);
            for b in parsed.bad_lines {
                prop_assert!(b.line >= 1);
            }
        }
    }
}
