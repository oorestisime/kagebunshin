//! Masking of secret values in `run`'s piped output.
//!
//! Each value of at least `masking.min_len` bytes is replaced by
//! `<redacted:KEY>`, and so is each such line of a multi-line value (a PEM
//! key printed line by line). Pure numbers and booleans are not masked: they
//! match too much ordinary output. Where two values match at the same place
//! the longer wins.
//!
//! Output is streamed, not buffered by line. A chunk is written as soon as it
//! arrives, except for its longest tail that could still be the start of a
//! value; that tail waits for the next chunk (or the end of the stream).
//!
//! Masking reduces leaks, it does not prevent them: a value split by other
//! output, encoded, or shorter than `min_len` gets through, and output to a
//! terminal is not masked at all.

use aho_corasick::{AhoCorasick, MatchKind};
use zeroize::Zeroizing;

/// The values to mask. Shared by the stdout and stderr streams.
pub struct Mask {
    /// `None` when there is nothing to mask.
    matcher: Option<AhoCorasick>,
    patterns: Vec<Zeroizing<Vec<u8>>>,
    /// `<redacted:KEY>` for each pattern.
    replacements: Vec<Vec<u8>>,
    longest: usize,
}

impl Mask {
    /// `vars` are key and value pairs.
    pub fn new<'a>(vars: impl IntoIterator<Item = (&'a str, &'a str)>, min_len: usize) -> Self {
        let mut patterns: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let mut replacements = Vec::new();
        let mut add = |key: &str, value: &str| {
            if maskable(value, min_len) && !patterns.iter().any(|p| **p == value.as_bytes()) {
                patterns.push(Zeroizing::new(value.as_bytes().to_vec()));
                replacements.push(format!("<redacted:{key}>").into_bytes());
            }
        };
        for (key, value) in vars {
            add(key, value);
            if value.contains('\n') {
                for line in value.lines() {
                    add(key, line);
                }
            }
        }
        let longest = patterns.iter().map(|p| p.len()).max().unwrap_or(0);
        #[expect(
            clippy::expect_used,
            reason = "at most a few thousand short patterns, well within the automaton limits"
        )]
        let matcher = (!patterns.is_empty()).then(|| {
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(patterns.iter().map(|p| p.as_slice()))
                .expect("a matcher over at most a few thousand short patterns")
        });
        Self {
            matcher,
            patterns,
            replacements,
            longest,
        }
    }

    pub fn stream(&self) -> Stream<'_> {
        Stream {
            mask: self,
            pending: Zeroizing::new(Vec::new()),
        }
    }

    /// Where the tail of `buf` that could still become a match starts: the
    /// first position whose rest is a proper prefix of some pattern.
    fn hold_from(&self, buf: &[u8]) -> usize {
        let from = buf.len().saturating_sub(self.longest.saturating_sub(1));
        (from..buf.len())
            .find(|&at| {
                let tail = &buf[at..];
                self.patterns
                    .iter()
                    .any(|p| p.len() > tail.len() && p.starts_with(tail))
            })
            .unwrap_or(buf.len())
    }
}

/// At least `min_len` bytes, and not a number or a boolean.
fn maskable(value: &str, min_len: usize) -> bool {
    let v = value.trim();
    let boolean = ["true", "false", "yes", "no", "on", "off"]
        .iter()
        .any(|b| v.eq_ignore_ascii_case(b));
    value.len() >= min_len && !boolean && v.parse::<f64>().is_err()
}

/// One output stream's state: the bytes held back so far.
pub struct Stream<'a> {
    mask: &'a Mask,
    pending: Zeroizing<Vec<u8>>,
}

impl Stream<'_> {
    /// Appends to `out` what can be written now.
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        if self.mask.matcher.is_none() {
            out.extend_from_slice(chunk);
            return;
        }
        // Grow by copying into a new zeroed-on-drop buffer, so no
        // reallocation leaves part of a value behind.
        if self.pending.capacity() < self.pending.len() + chunk.len() {
            let mut grown = Zeroizing::new(Vec::with_capacity(
                (self.pending.len() + chunk.len()).max(self.mask.longest * 2),
            ));
            grown.extend_from_slice(&self.pending);
            self.pending = grown;
        }
        self.pending.extend_from_slice(chunk);
        self.drain(out, false);
    }

    /// The end of the stream: writes whatever was held back.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        self.drain(out, true);
    }

    fn drain(&mut self, out: &mut Vec<u8>, end: bool) {
        let Some(matcher) = &self.mask.matcher else {
            out.extend_from_slice(&self.pending);
            self.pending.clear();
            return;
        };
        let buf = self.pending.as_slice();
        let hold_from = |at: usize| {
            if end {
                buf.len()
            } else {
                at + self.mask.hold_from(&buf[at..])
            }
        };
        // No match can start at or after `hold` and still be complete, and
        // none starting before it can grow into a longer one.
        let mut hold = hold_from(0);
        let mut done = 0;
        for m in matcher.find_iter(buf) {
            if m.start() >= hold {
                break;
            }
            out.extend_from_slice(&buf[done..m.start()]);
            out.extend_from_slice(&self.mask.replacements[m.pattern().as_usize()]);
            done = m.end();
            if done > hold {
                hold = hold_from(done);
            }
        }
        if hold > done {
            out.extend_from_slice(&buf[done..hold]);
            done = hold;
        }
        self.pending.drain(..done);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Canary, assert_no_canary};

    fn masked(mask: &Mask, chunks: &[&[u8]]) -> String {
        let mut stream = mask.stream();
        let mut out = Vec::new();
        for c in chunks {
            stream.push(c, &mut out);
        }
        stream.finish(&mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn a_value_split_at_every_offset_is_masked() {
        let c = Canary::new();
        let mask = Mask::new([("TOKEN", c.value())], 8);
        let text = format!("before {} after\n", c.value());
        let bytes = text.as_bytes();
        for at in 0..=bytes.len() {
            let out = masked(&mask, &[&bytes[..at], &bytes[at..]]);
            assert_no_canary(&c, &out);
            assert_eq!(out, "before <redacted:TOKEN> after\n", "split at {at}");
        }
        // One byte at a time.
        let chunks: Vec<&[u8]> = bytes.chunks(1).collect();
        assert_eq!(masked(&mask, &chunks), "before <redacted:TOKEN> after\n");
    }

    #[test]
    fn the_longest_overlapping_value_wins() {
        let mask = Mask::new([("SHORT", "abcdefgh"), ("LONG", "abcdefghijkl")], 8);
        assert_eq!(
            masked(&mask, &[b"x abcdefghijkl y abcdefgh z"]),
            "x <redacted:LONG> y <redacted:SHORT> z"
        );
        // The short value is complete before the long one could be: wait.
        assert_eq!(
            masked(&mask, &[b"x abcdefgh", b"ijkl y"]),
            "x <redacted:LONG> y"
        );
        assert_eq!(
            masked(&mask, &[b"x abcdefgh", b"ij y"]),
            "x <redacted:SHORT>ij y"
        );
    }

    #[test]
    fn only_a_possible_prefix_is_held_back() {
        let mask = Mask::new([("K", "secretvalue")], 8);
        let mut stream = mask.stream();
        let mut out = Vec::new();
        stream.push(b"progress: sec", &mut out);
        assert_eq!(out, b"progress: ");
        // A false start is released as soon as it cannot be a value.
        stream.push(b"ond", &mut out);
        assert_eq!(out, b"progress: second");
        stream.push(b" secretval", &mut out);
        assert_eq!(out, b"progress: second ");
        stream.finish(&mut out);
        assert_eq!(out, b"progress: second secretval");
    }

    #[test]
    fn each_line_of_a_multi_line_value_is_masked() {
        let pem = "-----BEGIN KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8w\nggE7AgEAAkEAq7BFUpkGp3+XQ\n-----END KEY-----";
        let mask = Mask::new([("PEM", pem)], 8);
        assert_eq!(masked(&mask, &[pem.as_bytes()]), "<redacted:PEM>");
        // Printed with other line endings, line by line.
        let crlf = pem.replace('\n', "\r\n");
        let out = masked(&mask, &[crlf.as_bytes()]);
        assert!(!out.contains("MIIBVQ") && !out.contains("ggE7Ag"), "{out}");
        assert_eq!(out.matches("<redacted:PEM>").count(), 4);
    }

    #[test]
    fn short_values_numbers_and_booleans_are_not_masked() {
        let mask = Mask::new(
            [
                ("SHORT", "abc1234"),
                ("PORT", "12345678"),
                ("RATE", "0.125000"),
                ("FLAG", " true   "),
                ("OK", "abcd1234"),
            ],
            8,
        );
        assert_eq!(
            masked(&mask, &[b"abc1234 12345678 0.125000  true    abcd1234"]),
            "abc1234 12345678 0.125000  true    <redacted:OK>"
        );
        let none = Mask::new([("A", "short")], 8);
        assert_eq!(masked(&none, &[b"short", b" text"]), "short text");
    }

    /// Many values and a few MiB of output, in pipe-sized chunks: every
    /// value is found and the run stays well within a debug build's budget.
    #[test]
    fn throughput() {
        let values: Vec<(String, String)> = (0..200)
            .map(|i| {
                (
                    format!("K{i}"),
                    format!("value-{i:04}-{}", "x".repeat(i % 40)),
                )
            })
            .collect();
        let mask = Mask::new(values.iter().map(|(k, v)| (k.as_str(), v.as_str())), 8);
        let mut text = Vec::new();
        let mut want = 0;
        while text.len() < 4 << 20 {
            text.extend_from_slice(b"some ordinary log line with value-12 in it, ");
            let (_, v) = &values[want % values.len()];
            text.extend_from_slice(v.as_bytes());
            text.push(b'\n');
            want += 1;
        }
        let started = std::time::Instant::now();
        let mut stream = mask.stream();
        let mut out = Vec::with_capacity(text.len());
        for chunk in text.chunks(8 * 1024) {
            stream.push(chunk, &mut out);
        }
        stream.finish(&mut out);
        let elapsed = started.elapsed();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(out.matches("<redacted:K").count(), want);
        assert!(!out.contains("value-0"));
        assert!(elapsed < std::time::Duration::from_secs(10), "{elapsed:?}");
    }

    #[test]
    fn non_utf8_output_passes_through() {
        let mask = Mask::new([("K", "secretvalue")], 8);
        let mut stream = mask.stream();
        let mut out = Vec::new();
        stream.push(b"\xff\xfe secretvalue \xc3", &mut out);
        stream.finish(&mut out);
        assert_eq!(out, b"\xff\xfe <redacted:K> \xc3");
    }
}
