//! The timestamp profile these documents use, and the arithmetic on it
//! (SPEC §18.1).
//!
//! §8.2 says `snapshot_time` is "RFC 3339 UTC, `Z` suffix", which was enough
//! while timestamps were only ever compared for equality or displayed. Once
//! two reports have to be shown to be *as of the same moment*, the format has
//! to be pinned tightly enough to subtract, and RFC 3339 is far wider than
//! what is wanted: offsets, lower-case `z`, `+00:00`, and unbounded fractional
//! digits all round-trip through it and all mean the same instant while
//! comparing unequal as strings.
//!
//! So this accepts exactly `YYYY-MM-DDTHH:MM:SS[.fff…]Z` and nothing else,
//! and converts to epoch seconds. Hand-rolled rather than pulling in a date
//! library: the format is fixed and narrow, the civil-days algorithm is
//! well-known, and the alternative is a dependency in a crate whose other
//! dependencies are all cryptographic.

/// Seconds since 1970-01-01T00:00:00Z. Signed, because nothing here forbids a
/// report about a date before 1970 and a panic is a worse answer than a
/// negative number.
pub type Epoch = i64;

/// Days from 1970-01-01 to a civil date, by Howard Hinnant's `days_from_civil`.
/// Valid for any proleptic Gregorian date; the era arithmetic is what keeps
/// leap years and century rules correct without a table.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = ((m + 9) % 12) as i64; // March = 0
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Parse the §18.1 profile. Returns `None` for anything outside it, including
/// timestamps that are valid RFC 3339 but not this profile.
pub fn parse(text: &str) -> Option<Epoch> {
    let bytes = text.as_bytes();
    // The shortest accepted form is exactly 20 bytes: 2026-01-01T00:00:00Z
    if bytes.len() < 20 || !text.is_ascii() {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        let slice = text.get(range)?;
        if !slice.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        slice.parse::<i64>().ok()
    };
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }

    let year = digits(0..4)?;
    let month = digits(5..7)? as u32;
    let day = digits(8..10)? as u32;
    let hour = digits(11..13)?;
    let minute = digits(14..16)?;
    let second = digits(17..19)?;

    // The tail is either `Z` or `.` followed by at least one digit and then
    // `Z`. Fractional seconds are accepted and discarded: they are below the
    // resolution anything here compares at, and rejecting them would refuse
    // timestamps Canton itself produces.
    match &text[19..] {
        "Z" => {}
        rest if rest.starts_with('.') && rest.ends_with('Z') => {
            let frac = &rest[1..rest.len() - 1];
            if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
        }
        _ => return None,
    }

    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    // Leap seconds are the one place a valid RFC 3339 second of 60 exists.
    // Canton does not emit them and admitting one would make the arithmetic
    // below ambiguous, so they are refused rather than silently clamped.
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Absolute difference in seconds, or `None` if either side is unparseable.
pub fn skew(a: &str, b: &str) -> Option<u64> {
    let (a, b) = (parse(a)?, parse(b)?);
    Some(a.abs_diff(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_is_zero() {
        assert_eq!(parse("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn a_known_instant_round_trips() {
        // 2026-01-01T00:00:00Z, checked against `date -u -d @1767225600`.
        assert_eq!(parse("2026-01-01T00:00:00Z"), Some(1_767_225_600));
    }

    /// The century rule is where hand-rolled date code usually breaks: 2000
    /// was a leap year and 1900 was not.
    #[test]
    fn leap_years_follow_the_gregorian_rules() {
        assert!(
            parse("2024-02-29T00:00:00Z").is_some(),
            "2024 is a leap year"
        );
        assert!(
            parse("2000-02-29T00:00:00Z").is_some(),
            "2000 is a leap year"
        );
        assert!(parse("1900-02-29T00:00:00Z").is_none(), "1900 is not");
        assert!(parse("2026-02-29T00:00:00Z").is_none(), "2026 is not");
        assert_eq!(
            skew("2024-02-28T00:00:00Z", "2024-03-01T00:00:00Z"),
            Some(2 * 86_400),
            "two days across a leap day"
        );
    }

    #[test]
    fn fractional_seconds_are_accepted_and_ignored() {
        assert_eq!(
            parse("2026-01-01T00:00:00.123456Z"),
            parse("2026-01-01T00:00:00Z")
        );
        assert!(parse("2026-01-01T00:00:00.Z").is_none(), "no digits");
    }

    /// Valid RFC 3339, outside this profile. Accepting these would mean two
    /// spellings of one instant compare unequal, or one instant compares equal
    /// to a different one.
    #[test]
    fn rfc_3339_forms_outside_the_profile_are_refused() {
        for text in [
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:00:00z",
            "2026-01-01 00:00:00Z",
            "2026-01-01T00:00:00",
            "2026-1-1T00:00:00Z",
            "20260101T000000Z",
            "",
            "not a time",
        ] {
            assert!(parse(text).is_none(), "{text:?} should be refused");
        }
    }

    #[test]
    fn out_of_range_components_are_refused() {
        for text in [
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-01-32T00:00:00Z",
            "2026-01-00T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:60:00Z",
            // A leap second: valid RFC 3339, ambiguous to subtract.
            "2026-06-30T23:59:60Z",
        ] {
            assert!(parse(text).is_none(), "{text:?} should be refused");
        }
    }

    #[test]
    fn skew_is_symmetric_and_absolute() {
        let a = "2026-08-09T00:00:00Z";
        let b = "2026-08-09T00:01:30Z";
        assert_eq!(skew(a, b), Some(90));
        assert_eq!(skew(b, a), Some(90));
        assert_eq!(skew(a, a), Some(0));
        assert_eq!(skew(a, "nonsense"), None);
    }

    #[test]
    fn ordering_matches_string_ordering_within_the_profile() {
        // Not required by anything, but if it ever stopped holding, a reader
        // sorting timestamps as strings would silently disagree with a reader
        // sorting them as instants.
        let mut times = [
            "2026-01-01T00:00:00Z",
            "2025-12-31T23:59:59Z",
            "2026-01-01T00:00:01Z",
        ];
        let mut by_instant = times;
        by_instant.sort_by_key(|t| parse(t).unwrap());
        times.sort();
        assert_eq!(times, by_instant);
    }
}
