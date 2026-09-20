//! Canonical metadata JSON (DESIGN.md §4.1).
//!
//! The design fixes a *canonical* encoding for metadata because it feeds MAC and
//! AEAD inputs: "metadata 为规范 JSON：UTF-8、键排序、无重复键、整数不用浮点表示；
//! 签名所需整数用十进制字符串".
//!
//! This module therefore deliberately does **not** use a general-purpose JSON
//! library. Metadata is an authenticated input and a parser-hardening target
//! (T20), so the codec here:
//!
//! * keeps object keys in a [`BTreeMap`], making re-encoding byte-stable and sorted;
//! * rejects duplicate keys instead of silently keeping the last one;
//! * rejects floats, because a value that round-trips as `1.0` would let two
//!   implementations disagree about the signed bytes;
//! * requires integers that do not fit `i64` to be carried as decimal strings, so
//!   a `u64` `packet_no`/`offset` cannot lose precision;
//! * enforces depth and length bounds *before* allocating or descending;
//! * reports typed errors, so a failure is never collapsed into a string.

use std::collections::BTreeMap;
use std::fmt;

use wsnet_limits::MAX_METADATA;

/// Maximum nesting depth accepted while parsing canonical metadata.
pub const MAX_CANON_DEPTH: usize = 16;

/// Errors produced while building, parsing, or encoding canonical metadata.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanonError {
    /// The input exceeds the caller-supplied or design-mandated byte bound.
    #[error("metadata is {actual} bytes, limit is {limit}")]
    TooLarge {
        /// Observed length.
        actual: usize,
        /// Enforced bound.
        limit: usize,
    },
    /// The input ended in the middle of a value.
    #[error("metadata ended unexpectedly at byte {0}")]
    UnexpectedEnd(usize),
    /// Bytes remained after the top-level value.
    #[error("unexpected trailing data at byte {0}")]
    TrailingData(usize),
    /// A byte appeared where the grammar did not allow it.
    #[error("unexpected byte {byte:#04x} at offset {offset}")]
    UnexpectedByte {
        /// The offending byte.
        byte: u8,
        /// Its offset in the input.
        offset: usize,
    },
    /// The same key appeared twice in one object.
    #[error("duplicate object key `{0}`")]
    DuplicateKey(String),
    /// A number was written with a fraction or exponent.
    #[error("metadata numbers must be integers, found a floating-point value at byte {0}")]
    FloatNotAllowed(usize),
    /// An integer literal did not fit `i64`.
    #[error("integer `{0}` does not fit i64; carry it as a decimal string")]
    IntegerTooLarge(String),
    /// A number literal was malformed (for example a leading zero).
    #[error("malformed number at byte {0}")]
    InvalidNumber(usize),
    /// Nesting exceeded [`MAX_CANON_DEPTH`].
    #[error("metadata nesting exceeds {MAX_CANON_DEPTH} levels")]
    TooDeep,
    /// A string was not valid UTF-8 after unescaping.
    #[error("string is not valid UTF-8")]
    InvalidUtf8,
    /// An escape sequence was not valid JSON.
    #[error("invalid escape sequence at byte {0}")]
    InvalidEscape(usize),
    /// A `\u` escape was not a valid code point (lone or malformed surrogate).
    #[error("invalid unicode escape at byte {0}")]
    InvalidUnicodeEscape(usize),
    /// A decimal-string field did not parse as an unsigned integer.
    #[error("field `{0}` is not a decimal unsigned integer")]
    NotDecimal(String),
    /// A field was absent.
    #[error("missing field `{0}`")]
    Missing(&'static str),
    /// A field had the wrong canonical type.
    #[error("field `{0}` has the wrong type")]
    WrongType(&'static str),
}

/// A canonical JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Canonical {
    /// JSON `null`.
    Null,
    /// JSON `true` / `false`.
    Bool(bool),
    /// A JSON integer that fits `i64`.
    Int(i64),
    /// A JSON string.
    Str(String),
    /// A JSON array, in written order.
    Array(Vec<Canonical>),
    /// A JSON object with sorted, unique keys.
    Object(BTreeMap<String, Canonical>),
}

impl Canonical {
    /// An empty object, spelled explicitly because `Canonical::object([])` has
    /// no way to infer the key type.
    pub fn empty_object() -> Self {
        Canonical::Object(BTreeMap::new())
    }

    /// Builds an object from key/value pairs; later duplicates win.
    pub fn object<I, K>(entries: I) -> Self
    where
        I: IntoIterator<Item = (K, Canonical)>,
        K: Into<String>,
    {
        Canonical::Object(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// Like [`Canonical::object`] but rejects a repeated key.
    pub fn try_object<I, K>(entries: I) -> Result<Self, CanonError>
    where
        I: IntoIterator<Item = (K, Canonical)>,
        K: Into<String>,
    {
        let mut map = BTreeMap::new();
        for (k, v) in entries {
            let k = k.into();
            if map.insert(k.clone(), v).is_some() {
                return Err(CanonError::DuplicateKey(k));
            }
        }
        Ok(Canonical::Object(map))
    }

    /// A string value.
    pub fn str(s: impl Into<String>) -> Self {
        Canonical::Str(s.into())
    }

    /// An integer value.
    pub fn int(v: i64) -> Self {
        Canonical::Int(v)
    }

    /// Carries an unsigned 64-bit integer as the decimal string the design
    /// mandates for signature-relevant integers.
    pub fn u64_decimal(v: u64) -> Self {
        Canonical::Str(v.to_string())
    }

    /// Borrows the object map, if this value is an object.
    pub fn as_object(&self) -> Option<&BTreeMap<String, Canonical>> {
        match self {
            Canonical::Object(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the named field, or [`CanonError::Missing`].
    pub fn field(&self, key: &'static str) -> Result<&Canonical, CanonError> {
        self.as_object()
            .and_then(|m| m.get(key))
            .ok_or(CanonError::Missing(key))
    }

    /// Borrows a string field.
    pub fn get_str(&self, key: &'static str) -> Result<&str, CanonError> {
        match self.field(key)? {
            Canonical::Str(s) => Ok(s),
            _ => Err(CanonError::WrongType(key)),
        }
    }

    /// Reads a field that must be a decimal-encoded unsigned integer.
    pub fn get_u64(&self, key: &'static str) -> Result<u64, CanonError> {
        let raw = self.get_str(key)?;
        raw.parse::<u64>().map_err(|_| CanonError::NotDecimal(key.into()))
    }

    /// Reads a field that must be an `i64` integer.
    pub fn get_i64(&self, key: &'static str) -> Result<i64, CanonError> {
        match self.field(key)? {
            Canonical::Int(v) => Ok(*v),
            _ => Err(CanonError::WrongType(key)),
        }
    }

    /// Reads a field that must be a bool.
    pub fn get_bool(&self, key: &'static str) -> Result<bool, CanonError> {
        match self.field(key)? {
            Canonical::Bool(v) => Ok(*v),
            _ => Err(CanonError::WrongType(key)),
        }
    }

    /// Reads a field that must be an array.
    pub fn get_array(&self, key: &'static str) -> Result<&[Canonical], CanonError> {
        match self.field(key)? {
            Canonical::Array(a) => Ok(a),
            _ => Err(CanonError::WrongType(key)),
        }
    }

    /// Encodes to the canonical byte form.
    ///
    /// The result is stable: encoding a parsed value reproduces the exact input
    /// bytes that a conforming peer would have produced.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        self.write(&mut out);
        out
    }

    /// Encodes and enforces the design metadata bound (§4.1).
    pub fn to_bounded_bytes(&self) -> Result<Vec<u8>, CanonError> {
        let bytes = self.to_bytes();
        if bytes.len() > MAX_METADATA {
            return Err(CanonError::TooLarge {
                actual: bytes.len(),
                limit: MAX_METADATA,
            });
        }
        Ok(bytes)
    }

    /// Parses canonical metadata, enforcing the design metadata bound.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonError> {
        Self::from_bytes_bounded(input, MAX_METADATA)
    }

    /// Parses canonical metadata with an explicit byte bound.
    ///
    /// The bound is checked before any decoding work, per §4.1's
    /// "先限长再分配/解码".
    pub fn from_bytes_bounded(input: &[u8], limit: usize) -> Result<Self, CanonError> {
        if input.len() > limit {
            return Err(CanonError::TooLarge {
                actual: input.len(),
                limit,
            });
        }
        let mut parser = Parser {
            input,
            pos: 0,
            depth: 0,
        };
        parser.skip_ws();
        let value = parser.parse_value()?;
        parser.skip_ws();
        if parser.pos != input.len() {
            return Err(CanonError::TrailingData(parser.pos));
        }
        Ok(value)
    }

    /// Maximum nesting depth of this value (a scalar has depth 1).
    pub fn depth(&self) -> usize {
        match self {
            Canonical::Array(items) => 1 + items.iter().map(Canonical::depth).max().unwrap_or(0),
            Canonical::Object(map) => 1 + map.values().map(Canonical::depth).max().unwrap_or(0),
            _ => 1,
        }
    }

    /// Returns `true` when `input` is already in canonical form.
    pub fn is_canonical(input: &[u8]) -> Result<bool, CanonError> {
        let parsed = Canonical::from_bytes(input)?;
        Ok(parsed.to_bytes() == input)
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Canonical::Null => out.extend_from_slice(b"null"),
            Canonical::Bool(true) => out.extend_from_slice(b"true"),
            Canonical::Bool(false) => out.extend_from_slice(b"false"),
            Canonical::Int(v) => out.extend_from_slice(v.to_string().as_bytes()),
            Canonical::Str(s) => write_json_string(s, out),
            Canonical::Array(items) => {
                out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    item.write(out);
                }
                out.push(b']');
            }
            Canonical::Object(map) => {
                out.push(b'{');
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    write_json_string(k, out);
                    out.push(b':');
                    v.write(out);
                }
                out.push(b'}');
            }
        }
    }
}

impl fmt::Display for Canonical {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.to_bytes()))
    }
}

/// Writes a JSON string literal. Non-ASCII is emitted as raw UTF-8, and control
/// characters use the shortest standard escape, so the encoding is deterministic.
fn write_json_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn bump(&mut self) -> Result<u8, CanonError> {
        let byte = self
            .peek()
            .ok_or(CanonError::UnexpectedEnd(self.pos))?;
        self.pos += 1;
        Ok(byte)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            match b {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn expect_literal(&mut self, word: &[u8], value: Canonical) -> Result<Canonical, CanonError> {
        let end = self.pos + word.len();
        if end > self.input.len() {
            return Err(CanonError::UnexpectedEnd(self.pos));
        }
        if &self.input[self.pos..end] != word {
            return Err(CanonError::UnexpectedByte {
                byte: self.input[self.pos],
                offset: self.pos,
            });
        }
        self.pos = end;
        Ok(value)
    }

    fn parse_value(&mut self) -> Result<Canonical, CanonError> {
        match self.peek().ok_or(CanonError::UnexpectedEnd(self.pos))? {
            b'n' => self.expect_literal(b"null", Canonical::Null),
            b't' => self.expect_literal(b"true", Canonical::Bool(true)),
            b'f' => self.expect_literal(b"false", Canonical::Bool(false)),
            b'"' => Ok(Canonical::Str(self.parse_string()?)),
            b'[' => self.parse_array(),
            b'{' => self.parse_object(),
            b'-' | b'0'..=b'9' => self.parse_number(),
            byte => Err(CanonError::UnexpectedByte {
                byte,
                offset: self.pos,
            }),
        }
    }

    /// Descends one level, enforcing [`MAX_CANON_DEPTH`] before recursing.
    fn enter(&mut self) -> Result<(), CanonError> {
        if self.depth >= MAX_CANON_DEPTH {
            return Err(CanonError::TooDeep);
        }
        self.depth += 1;
        Ok(())
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }

    fn parse_array(&mut self) -> Result<Canonical, CanonError> {
        self.enter()?;
        self.pos += 1; // consume '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            self.leave();
            return Ok(Canonical::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.bump()? {
                b',' => continue,
                b']' => break,
                byte => {
                    return Err(CanonError::UnexpectedByte {
                        byte,
                        offset: self.pos - 1,
                    })
                }
            }
        }
        self.leave();
        Ok(Canonical::Array(items))
    }

    fn parse_object(&mut self) -> Result<Canonical, CanonError> {
        self.enter()?;
        self.pos += 1; // consume '{'
        let mut map: BTreeMap<String, Canonical> = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            self.leave();
            return Ok(Canonical::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(CanonError::UnexpectedByte {
                    byte: self.peek().unwrap_or(0),
                    offset: self.pos,
                });
            }
            let key = self.parse_string()?;
            self.skip_ws();
            match self.bump()? {
                b':' => {}
                byte => {
                    return Err(CanonError::UnexpectedByte {
                        byte,
                        offset: self.pos - 1,
                    })
                }
            }
            self.skip_ws();
            let value = self.parse_value()?;
            if map.insert(key.clone(), value).is_some() {
                return Err(CanonError::DuplicateKey(key));
            }
            self.skip_ws();
            match self.bump()? {
                b',' => continue,
                b'}' => break,
                byte => {
                    return Err(CanonError::UnexpectedByte {
                        byte,
                        offset: self.pos - 1,
                    })
                }
            }
        }
        self.leave();
        Ok(Canonical::Object(map))
    }

    fn parse_number(&mut self) -> Result<Canonical, CanonError> {
        let start = self.pos;
        let negative = if self.peek() == Some(b'-') {
            self.pos += 1;
            true
        } else {
            false
        };

        let digits_start = self.pos;
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                // JSON forbids a leading zero, so `01` must not parse as `0`.
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(CanonError::InvalidNumber(self.pos));
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(CanonError::InvalidNumber(start)),
        }
        let digits_end = self.pos;

        // A fraction or exponent makes this a float, which canonical metadata
        // forbids outright rather than rounding.
        if matches!(self.peek(), Some(b'.') | Some(b'e') | Some(b'E')) {
            return Err(CanonError::FloatNotAllowed(self.pos));
        }

        let text = std::str::from_utf8(&self.input[digits_start..digits_end])
            .map_err(|_| CanonError::InvalidNumber(start))?;
        let magnitude = text
            .parse::<i128>()
            .map_err(|_| CanonError::IntegerTooLarge(text.to_string()))?;
        let signed = if negative { -magnitude } else { magnitude };
        let value = i64::try_from(signed)
            .map_err(|_| CanonError::IntegerTooLarge(format!("{}{text}", if negative { "-" } else { "" })))?;
        Ok(Canonical::Int(value))
    }

    fn parse_string(&mut self) -> Result<String, CanonError> {
        self.pos += 1; // consume opening quote
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            let byte = self.bump()?;
            match byte {
                b'"' => break,
                b'\\' => self.parse_escape(&mut bytes)?,
                0x00..=0x1f => {
                    return Err(CanonError::UnexpectedByte {
                        byte,
                        offset: self.pos - 1,
                    })
                }
                _ => bytes.push(byte),
            }
        }
        String::from_utf8(bytes).map_err(|_| CanonError::InvalidUtf8)
    }

    fn parse_escape(&mut self, out: &mut Vec<u8>) -> Result<(), CanonError> {
        let esc_pos = self.pos;
        match self.bump()? {
            b'"' => out.push(b'"'),
            b'\\' => out.push(b'\\'),
            b'/' => out.push(b'/'),
            b'b' => out.push(0x08),
            b'f' => out.push(0x0c),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'u' => {
                let first = self.read_hex4()?;
                let code = if (0xd800..=0xdbff).contains(&first) {
                    // A high surrogate must be followed by a low surrogate.
                    if self.bump()? != b'\\' || self.bump()? != b'u' {
                        return Err(CanonError::InvalidUnicodeEscape(esc_pos));
                    }
                    let second = self.read_hex4()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(CanonError::InvalidUnicodeEscape(esc_pos));
                    }
                    let combined =
                        0x1_0000u32 + ((first as u32 - 0xd800) << 10) + (second as u32 - 0xdc00);
                    char::from_u32(combined).ok_or(CanonError::InvalidUnicodeEscape(esc_pos))?
                } else if (0xdc00..=0xdfff).contains(&first) {
                    // A lone low surrogate is not a code point.
                    return Err(CanonError::InvalidUnicodeEscape(esc_pos));
                } else {
                    char::from_u32(first as u32).ok_or(CanonError::InvalidUnicodeEscape(esc_pos))?
                };
                let mut buf = [0u8; 4];
                out.extend_from_slice(code.encode_utf8(&mut buf).as_bytes());
            }
            _ => return Err(CanonError::InvalidEscape(esc_pos)),
        }
        Ok(())
    }

    fn read_hex4(&mut self) -> Result<u16, CanonError> {
        let start = self.pos;
        let mut value: u16 = 0;
        for _ in 0..4 {
            let byte = self.bump()?;
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err(CanonError::InvalidUnicodeEscape(start)),
            };
            value = (value << 4) | u16::from(digit);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_keys_are_sorted_and_round_trip() {
        let value = Canonical::object([
            ("zulu", Canonical::int(1)),
            ("alpha", Canonical::int(2)),
            ("mike", Canonical::int(3)),
        ]);
        let bytes = value.to_bytes();
        assert_eq!(bytes, br#"{"alpha":2,"mike":3,"zulu":1}"#);
        assert_eq!(Canonical::from_bytes(&bytes).unwrap(), value);
        assert!(Canonical::is_canonical(&bytes).unwrap());
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        assert_eq!(
            Canonical::from_bytes(br#"{"a":1,"a":2}"#).unwrap_err(),
            CanonError::DuplicateKey("a".into())
        );
    }

    #[test]
    fn nested_duplicate_keys_are_rejected() {
        assert_eq!(
            Canonical::from_bytes(br#"{"outer":{"x":1,"x":2}}"#).unwrap_err(),
            CanonError::DuplicateKey("x".into())
        );
    }

    #[test]
    fn floats_are_rejected() {
        assert!(matches!(
            Canonical::from_bytes(br#"{"n":1.5}"#).unwrap_err(),
            CanonError::FloatNotAllowed(_)
        ));
        assert!(matches!(
            Canonical::from_bytes(br#"{"n":1e3}"#).unwrap_err(),
            CanonError::FloatNotAllowed(_)
        ));
    }

    #[test]
    fn oversized_integers_must_be_decimal_strings() {
        assert_eq!(
            Canonical::from_bytes(br#"{"n":9223372036854775808}"#).unwrap_err(),
            CanonError::IntegerTooLarge("9223372036854775808".into())
        );
        assert_eq!(
            Canonical::from_bytes(b"18446744073709551615").unwrap_err(),
            CanonError::IntegerTooLarge("18446744073709551615".into())
        );

        // The design-approved spelling round-trips at full u64 precision.
        let ok = Canonical::from_bytes(br#"{"n":"18446744073709551615"}"#).unwrap();
        assert_eq!(ok.get_u64("n").unwrap(), u64::MAX);
    }

    #[test]
    fn i64_boundaries_are_exact() {
        assert_eq!(
            Canonical::from_bytes(b"-9223372036854775808").unwrap(),
            Canonical::Int(i64::MIN)
        );
        assert_eq!(
            Canonical::from_bytes(b"9223372036854775807").unwrap(),
            Canonical::Int(i64::MAX)
        );
        assert!(Canonical::from_bytes(b"-9223372036854775809").is_err());
    }

    #[test]
    fn leading_zeros_are_rejected() {
        assert!(matches!(
            Canonical::from_bytes(b"01").unwrap_err(),
            CanonError::InvalidNumber(_)
        ));
        assert_eq!(Canonical::from_bytes(b"0").unwrap(), Canonical::Int(0));
    }

    #[test]
    fn length_is_checked_before_decoding() {
        let big = vec![b'a'; 64];
        assert_eq!(
            Canonical::from_bytes_bounded(&big, 16).unwrap_err(),
            CanonError::TooLarge {
                actual: 64,
                limit: 16
            }
        );
    }

    #[test]
    fn metadata_bound_is_enforced_on_encode() {
        let value = Canonical::object([("blob", Canonical::str("x".repeat(MAX_METADATA + 1)))]);
        assert!(matches!(
            value.to_bounded_bytes().unwrap_err(),
            CanonError::TooLarge { .. }
        ));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        assert!(matches!(
            Canonical::from_bytes(br#"{"a":1} trailing"#).unwrap_err(),
            CanonError::TrailingData(_)
        ));
    }

    #[test]
    fn depth_limit_is_enforced_without_stack_growth() {
        let deep = "[".repeat(MAX_CANON_DEPTH + 1);
        assert_eq!(Canonical::from_bytes(deep.as_bytes()).unwrap_err(), CanonError::TooDeep);

        let ok = "[".repeat(MAX_CANON_DEPTH) + &"]".repeat(MAX_CANON_DEPTH);
        assert!(Canonical::from_bytes(ok.as_bytes()).is_ok());
    }

    #[test]
    fn unicode_escapes_and_surrogates() {
        assert_eq!(
            Canonical::from_bytes(br#""\u0041""#).unwrap(),
            Canonical::Str("A".into())
        );
        // U+1F600 as a surrogate pair.
        assert_eq!(
            Canonical::from_bytes(br#""\ud83d\ude00""#).unwrap(),
            Canonical::Str("\u{1f600}".into())
        );
        // A lone high surrogate is not a code point.
        assert!(Canonical::from_bytes(br#""\ud83d""#).is_err());
        assert!(Canonical::from_bytes(br#""\udc00""#).is_err());
    }

    #[test]
    fn string_escapes_round_trip_canonically() {
        let value = Canonical::str("a\"b\\c\nd\te\u{1f600}");
        let bytes = value.to_bytes();
        assert_eq!(Canonical::from_bytes(&bytes).unwrap(), value);
        assert!(Canonical::is_canonical(&bytes).unwrap());
    }

    #[test]
    fn raw_control_characters_are_rejected() {
        assert!(Canonical::from_bytes(b"\"a\nb\"").is_err());
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        assert_eq!(
            Canonical::from_bytes(&[b'"', 0xff, 0xfe, b'"']).unwrap_err(),
            CanonError::InvalidUtf8
        );
    }

    #[test]
    fn truncation_and_garbage_do_not_panic() {
        let cases: &[&[u8]] = &[
            b"",
            b"{",
            b"{\"a\":",
            b"{\"a\":1",
            b"[",
            b"[1,",
            b"\"unclosed",
            b"nul",
            b"tru",
            b"-",
            b"{\"a\"}",
            b"{\"a\" 1}",
            b"[,]",
            b"\xff\xfe",
            b"{\"a\":1,}",
        ];
        for input in cases {
            // Must return a typed error, never panic.
            let _ = Canonical::from_bytes(input);
        }
        // Trailing commas are not valid JSON.
        assert!(Canonical::from_bytes(b"{\"a\":1,}").is_err());
        assert!(Canonical::from_bytes(b"[1,]").is_err());
    }

    #[test]
    fn depth_helper_is_computed() {
        let nested = Canonical::from_bytes(br#"{"a":{"b":{"c":1}}}"#).unwrap();
        assert_eq!(nested.depth(), 4);
    }

    #[test]
    fn try_object_rejects_duplicates() {
        assert_eq!(
            Canonical::try_object([("a", Canonical::int(1)), ("a", Canonical::int(2))]).unwrap_err(),
            CanonError::DuplicateKey("a".into())
        );
    }

    #[test]
    fn canonical_encoding_is_idempotent() {
        let inputs: &[&[u8]] = &[
            br#"{}"#,
            br#"[]"#,
            br#"{"a":[1,2,{"b":"c"}]}"#,
            br#"{"z":null,"a":true}"#,
        ];
        for input in inputs {
            let value = Canonical::from_bytes(input).unwrap();
            let once = value.to_bytes();
            let twice = Canonical::from_bytes(&once).unwrap().to_bytes();
            assert_eq!(once, twice);
            assert!(Canonical::is_canonical(&once).unwrap());
        }
    }
}
