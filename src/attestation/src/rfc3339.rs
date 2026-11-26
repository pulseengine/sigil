//! RFC 3339 timestamps, as attestations and transparency-log entries carry them.
//!
//! These replace chrono's `to_rfc3339`, `to_rfc3339_opts(Secs, true)` and
//! `DateTime::parse_from_rfc3339` (RUSTSEC-2026-0543: chrono is unmaintained).
//! Both directions keep chrono's exact behavior, because the strings end up
//! inside signed and attested JSON that verifiers already in the field read:
//!
//! - [`format`] writes what chrono's `to_rfc3339` wrote for a UTC time:
//!   `+00:00` offset, and 0, 3, 6 or 9 fractional digits, whichever is the
//!   shortest exact form.
//! - [`parse`] accepts exactly chrono's RFC 3339 grammar and nothing more:
//!   `YYYY-MM-DD`, then `T`, `t` or a space, `HH:MM:SS`, an optional `.`
//!   with one or more digits (digits past the ninth are ignored), then `Z`,
//!   `z` or `±HH:MM` (also U+2212 MINUS SIGN) with an absolute value under
//!   24 hours. Second 60 (a leap second) reads as second 59.
//!
//! One deliberate difference: jiff's [`Timestamp`] ends at
//! 9999-12-30T22:00:00.999999999Z, where chrono reached year 262143. A
//! string past that instant (a year-9999 date within about 26 hours of year
//! 10000) is still accepted, and reads as [`Timestamp::MAX`]. That keeps
//! RFC 5280's "no well-defined expiration" value, `99991231235959Z`, valid;
//! every comparison in this crate is unaffected by the clamp.
//!
//! jiff's own parser is deliberately not used for [`parse`]: it accepts a
//! wider ISO 8601 / Temporal grammar (missing seconds, bracketed time-zone
//! annotations, basic format), and a verifier that silently accepts more
//! timestamp shapes than before is a change this module must not make.

use jiff::SignedDuration;
use jiff::civil::{Date, DateTime, Time};
use jiff::fmt::temporal::DateTimePrinter;
use jiff::tz::Offset;

/// The instant type the library API takes, re-exported so callers need not
/// depend on jiff directly.
pub use jiff::Timestamp;

/// Why a string is not an RFC 3339 timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Shorter than `YYYY-MM-DDTHH:MM:SS` plus an offset.
    TooShort,
    /// A character where the grammar has no place for it.
    Invalid,
    /// Well formed, but a field is out of range (month 13, hour 24, Feb 30,
    /// an offset of 24 hours or more).
    OutOfRange,
    /// Characters after the offset.
    TooLong,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ParseError::TooShort => "premature end of input",
            ParseError::Invalid => "input contains invalid characters",
            ParseError::OutOfRange => "input is out of range",
            ParseError::TooLong => "trailing input",
        })
    }
}

impl std::error::Error for ParseError {}

/// The current time, formatted by [`format`].
pub fn now() -> String {
    format(Timestamp::now())
}

/// `ts` in UTC with a `+00:00` offset and 0, 3, 6 or 9 fractional digits:
/// byte for byte what chrono's `DateTime<Utc>::to_rfc3339` wrote, for years
/// 0 to 9999. Years before 0 print in jiff's six-digit form (`-000001`, where
/// chrono wrote `-0001`); neither form parses back with [`parse`].
pub fn format(ts: Timestamp) -> String {
    let nanos = ts.subsec_nanosecond();
    let precision = if nanos == 0 {
        0
    } else if nanos % 1_000_000 == 0 {
        3
    } else if nanos % 1_000 == 0 {
        6
    } else {
        9
    };
    let mut out = String::with_capacity(35);
    DateTimePrinter::new()
        .precision(Some(precision))
        .print_timestamp_with_offset(&ts, Offset::UTC, &mut out)
        .expect("writing to a String cannot fail");
    out
}

/// Whole Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`: what chrono's
/// `to_rfc3339_opts(SecondsFormat::Secs, true)` wrote. `None` when the year
/// is before 0 or `secs` is past jiff's range: chrono wrote a string for a
/// year before 0 that its own RFC 3339 parser then rejected.
pub fn format_unix_secs_z(secs: i64) -> Option<String> {
    // 0000-01-01T00:00:00Z
    if secs < -62_167_219_200 {
        return None;
    }
    let ts = Timestamp::from_second(secs).ok()?;
    let mut out = String::with_capacity(20);
    DateTimePrinter::new()
        .precision(Some(0))
        .print_timestamp(&ts, &mut out)
        .expect("writing to a String cannot fail");
    Some(out)
}

/// Parse an RFC 3339 timestamp with chrono's `parse_from_rfc3339` grammar.
/// See the module documentation for exactly what is accepted.
pub fn parse(s: &str) -> Result<Timestamp, ParseError> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return Err(ParseError::TooShort);
    }
    let d = |i: usize| -> Result<i32, ParseError> {
        if b[i].is_ascii_digit() {
            Ok(i32::from(b[i] - b'0'))
        } else {
            Err(ParseError::Invalid)
        }
    };
    let year = d(0)? * 1000 + d(1)? * 100 + d(2)? * 10 + d(3)?;
    if b[4] != b'-' {
        return Err(ParseError::Invalid);
    }
    let month = d(5)? * 10 + d(6)?;
    if b[7] != b'-' {
        return Err(ParseError::Invalid);
    }
    let day = d(8)? * 10 + d(9)?;
    // chrono validates the date before it looks at the time.
    let date =
        Date::new(year as i16, month as i8, day as i8).map_err(|_| ParseError::OutOfRange)?;
    if !matches!(b[10], b'T' | b't' | b' ') {
        return Err(ParseError::Invalid);
    }
    let hour = d(11)? * 10 + d(12)?;
    if b[13] != b':' {
        return Err(ParseError::Invalid);
    }
    let minute = d(14)? * 10 + d(15)?;
    if b[16] != b':' {
        return Err(ParseError::Invalid);
    }
    let mut second = d(17)? * 10 + d(18)?;
    // RFC 3339 allows a leap second; chrono reads it as second 59 (its Unix
    // time is that of second 59).
    if second == 60 {
        second = 59;
    }

    let mut rest = &b[19..];
    let mut nanos = 0i32;
    if rest.first() == Some(&b'.') {
        rest = &rest[1..];
        let digits = rest.iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 {
            return Err(if rest.is_empty() {
                ParseError::TooShort
            } else {
                ParseError::Invalid
            });
        }
        for (i, c) in rest[..digits.min(9)].iter().enumerate() {
            nanos += i32::from(c - b'0') * 10i32.pow(8 - i as u32);
        }
        rest = &rest[digits..];
    }

    let time = Time::new(hour as i8, minute as i8, second as i8, nanos)
        .map_err(|_| ParseError::OutOfRange)?;

    let offset_secs = parse_offset(&mut rest)?;
    if !rest.is_empty() {
        return Err(ParseError::TooLong);
    }
    if offset_secs.abs() >= 86_400 {
        return Err(ParseError::OutOfRange);
    }
    let offset = Offset::from_seconds(offset_secs).map_err(|_| ParseError::OutOfRange)?;
    match offset.to_timestamp(DateTime::from_parts(date, time)) {
        Ok(ts) => Ok(ts),
        // Four-digit years and offsets under 24 hours can only leave jiff's
        // range at the top, in year 9999 (module docs).
        Err(_) if year == 9999 => Ok(Timestamp::MAX),
        Err(_) => Err(ParseError::OutOfRange),
    }
}

/// Unix seconds as a [`Timestamp`], clamped to jiff's range. chrono's
/// `from_timestamp(secs, 0)` reached year 262143; certificate times
/// (`99991231235959Z`) go past jiff's end in year 9999.
pub fn from_unix_secs_clamped(secs: i64) -> Timestamp {
    Timestamp::from_second(secs).unwrap_or(if secs > 0 {
        Timestamp::MAX
    } else {
        Timestamp::MIN
    })
}

/// `Z`, `z` or `±HH:MM` (`-` may also be U+2212), as chrono's
/// `timezone_offset` with colon required, Zulu allowed and minutes required.
fn parse_offset(rest: &mut &[u8]) -> Result<i32, ParseError> {
    let s = *rest;
    match s.first() {
        None => return Err(ParseError::TooShort),
        Some(b'Z' | b'z') => {
            *rest = &s[1..];
            return Ok(0);
        }
        _ => {}
    }
    let (negative, s) = if let Some(t) = s.strip_prefix(b"+") {
        (false, t)
    } else if let Some(t) = s.strip_prefix(b"-") {
        (true, t)
    } else if let Some(t) = s.strip_prefix("\u{2212}".as_bytes()) {
        (true, t)
    } else {
        return Err(ParseError::Invalid);
    };
    if s.len() < 2 {
        return Err(ParseError::TooShort);
    }
    if !(s[0].is_ascii_digit() && s[1].is_ascii_digit()) {
        return Err(ParseError::Invalid);
    }
    let hours = i32::from(s[0] - b'0') * 10 + i32::from(s[1] - b'0');
    let s = &s[2..];
    let s = match s.first() {
        Some(b':') => &s[1..],
        Some(_) => return Err(ParseError::Invalid),
        None => return Err(ParseError::TooShort),
    };
    if s.len() < 2 {
        return Err(ParseError::TooShort);
    }
    let minutes = match (s[0], s[1]) {
        (m1 @ b'0'..=b'5', m2 @ b'0'..=b'9') => i32::from(m1 - b'0') * 10 + i32::from(m2 - b'0'),
        (b'6'..=b'9', b'0'..=b'9') => return Err(ParseError::OutOfRange),
        _ => return Err(ParseError::Invalid),
    };
    *rest = &s[2..];
    let secs = hours * 3600 + minutes * 60;
    Ok(if negative { -secs } else { secs })
}

/// Whole Unix seconds, rounded toward negative infinity: chrono's
/// `DateTime::timestamp()`. (jiff's `as_second` rounds toward zero, which
/// differs before 1970 when there is a fractional second.)
pub fn unix_secs(ts: Timestamp) -> i64 {
    let secs = ts.as_second();
    if ts.subsec_nanosecond() < 0 {
        secs - 1
    } else {
        secs
    }
}

/// `SignedDuration` from a `std::time::Duration`, saturating at the maximum
/// (chrono code used `TimeDelta::from_std(..).unwrap_or(TimeDelta::MAX)`).
pub fn saturating_signed(d: std::time::Duration) -> SignedDuration {
    SignedDuration::try_from(d).unwrap_or(SignedDuration::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected values recorded from chrono 0.4.44's `parse_from_rfc3339`
    /// (Unix seconds and subsecond nanos, or rejected), by a differential run
    /// over this corpus plus 2,000,000 generated strings before chrono was
    /// removed. See the PR that introduced this module.
    #[test]
    fn parse_matches_chrono_on_the_recorded_corpus() {
        let accept: &[(&str, i64, i32)] = &[
            ("2026-11-22T12:00:00Z", 1_795_348_800, 0),
            ("2026-11-22t12:00:00z", 1_795_348_800, 0),
            ("2026-11-22 12:00:00+00:00", 1_795_348_800, 0),
            ("2026-11-22T12:00:00.5Z", 1_795_348_800, 500_000_000),
            ("2026-11-22T12:00:00.123456789Z", 1_795_348_800, 123_456_789),
            (
                "2026-11-22T12:00:00.1234567891234Z",
                1_795_348_800,
                123_456_789,
            ),
            ("2026-11-22T13:30:00+01:30", 1_795_348_800, 0),
            ("2026-11-22T10:00:00-02:00", 1_795_348_800, 0),
            ("2026-11-22T10:00:00\u{2212}02:00", 1_795_348_800, 0),
            ("2026-11-22T12:00:00+23:59", 1_795_262_460, 0),
            ("2016-12-31T23:59:60Z", 1_483_228_799, 0),
            ("2026-11-22T12:34:60Z", 1_795_350_899, 0),
            ("1970-01-01T00:00:00Z", 0, 0),
            ("0000-01-01T00:00:00Z", -62_167_219_200, 0),
            ("9999-12-30T22:00:00Z", 253_402_207_200, 0), // jiff's last whole second
            // Past jiff's range: accepted, clamped to Timestamp::MAX (module docs).
            ("9999-12-31T23:59:59Z", 253_402_207_200, 999_999_999),
            ("9999-12-30T23:00:00+00:59", 253_402_207_200, 999_999_999),
            ("2024-02-29T00:00:00Z", 1_709_164_800, 0),
        ];
        for (s, secs, nanos) in accept {
            let ts = parse(s).unwrap_or_else(|e| panic!("{s:?} rejected: {e}"));
            assert_eq!(
                (ts.as_second(), ts.subsec_nanosecond()),
                (*secs, *nanos),
                "{s:?}"
            );
        }
        let reject: &[(&str, ParseError)] = &[
            ("", ParseError::TooShort),
            ("2026-11-22T12:00:00", ParseError::TooShort),
            ("2026-11-22T12:00Z", ParseError::TooShort),
            ("2026-11-22T12:00:00.Z", ParseError::Invalid),
            ("2026-11-22T12:00:00.", ParseError::TooShort),
            ("2026-11-22T12:00:00+0100", ParseError::Invalid),
            ("2026-11-22T12:00:00+01", ParseError::TooShort),
            ("2026-11-22T12:00:00+24:00", ParseError::OutOfRange),
            ("2026-11-22T12:00:00+01:60", ParseError::OutOfRange),
            ("2026-11-22T12:00:00Z[UTC]", ParseError::TooLong),
            ("2026-11-22T12:00:00ZZ", ParseError::TooLong),
            ("2026-11-22T12:00:00 Z", ParseError::Invalid),
            ("2026-11-22T24:00:00Z", ParseError::OutOfRange),
            ("2026-11-22T12:60:00Z", ParseError::OutOfRange),
            ("2026-11-22T12:00:61Z", ParseError::OutOfRange),
            ("2026-13-01T00:00:00Z", ParseError::OutOfRange),
            ("2025-02-29T00:00:00Z", ParseError::OutOfRange),
            ("2026-11-22X12:00:00Z", ParseError::Invalid),
            ("20261122T120000Z", ParseError::TooShort),
            ("+2026-11-22T12:00:00Z", ParseError::Invalid),
            ("2026-11-22T12:00:00UTC", ParseError::Invalid),
            ("1787295161", ParseError::TooShort),
        ];
        for (s, err) in reject {
            assert_eq!(parse(s), Err(*err), "{s:?}");
        }
    }

    #[test]
    fn format_matches_chrono_to_rfc3339() {
        let at = |secs: i64, nanos: i32| Timestamp::new(secs, nanos).unwrap();
        assert_eq!(format(at(1_795_348_800, 0)), "2026-11-22T12:00:00+00:00");
        assert_eq!(
            format(at(1_795_348_800, 500_000_000)),
            "2026-11-22T12:00:00.500+00:00"
        );
        assert_eq!(
            format(at(1_795_348_800, 120_000)),
            "2026-11-22T12:00:00.000120+00:00"
        );
        assert_eq!(
            format(at(1_795_348_800, 1)),
            "2026-11-22T12:00:00.000000001+00:00"
        );
        assert_eq!(format(at(0, 0)), "1970-01-01T00:00:00+00:00");
    }

    #[test]
    fn format_unix_secs_z_matches_chrono_secs_z() {
        assert_eq!(
            format_unix_secs_z(1_787_295_161).as_deref(),
            Some("2026-08-21T06:52:41Z")
        );
        assert_eq!(
            format_unix_secs_z(0).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        assert_eq!(format_unix_secs_z(i64::MAX), None);
        assert_eq!(format_unix_secs_z(-62_167_219_201), None); // -0001-12-31T23:59:59Z
    }

    #[test]
    fn unix_secs_floors_and_clamps() {
        assert_eq!(unix_secs(Timestamp::new(-1, -500_000_000).unwrap()), -2);
        assert_eq!(unix_secs(Timestamp::new(5, 500_000_000).unwrap()), 5);
        // 9999-12-31T23:59:59Z, a certificate's "no expiry"
        assert_eq!(from_unix_secs_clamped(253_402_300_799), Timestamp::MAX);
        assert_eq!(from_unix_secs_clamped(i64::MIN), Timestamp::MIN);
        assert_eq!(
            from_unix_secs_clamped(1_795_348_800).as_second(),
            1_795_348_800
        );
    }

    #[test]
    fn now_round_trips() {
        let s = now();
        let ts = parse(&s).expect("now() must parse");
        assert_eq!(format(ts), s);
    }
}
