//! Formats database timestamps for HTTP responses without changing their wire representation.

use jiff::tz::Offset;
use jiff_sqlx::Timestamp;

/// Formats UTC with a numeric offset and the existing 0/3/6/9 fractional digit convention.
pub(super) fn rfc3339(timestamp: Timestamp) -> String {
    let timestamp = timestamp.to_jiff();
    let nanos = timestamp.subsec_nanosecond();
    let precision = if nanos == 0 {
        0
    } else if nanos % 1_000_000 == 0 {
        3
    } else if nanos % 1_000 == 0 {
        6
    } else {
        9
    };
    format!("{:.precision$}", timestamp.display_with_offset(Offset::UTC))
}

#[cfg(test)]
mod tests {
    use super::rfc3339;

    #[test]
    fn rfc3339_preserves_numeric_offset_and_fractional_precision() -> Result<(), jiff::Error> {
        for (input, expected) in [
            ("2026-01-02T03:04:05Z", "2026-01-02T03:04:05+00:00"),
            ("2026-01-02T03:04:05.12Z", "2026-01-02T03:04:05.120+00:00"),
            (
                "2026-01-02T03:04:05.12345Z",
                "2026-01-02T03:04:05.123450+00:00",
            ),
            (
                "2026-01-02T03:04:05.12345678Z",
                "2026-01-02T03:04:05.123456780+00:00",
            ),
        ] {
            let timestamp = input.parse::<jiff::Timestamp>()?;
            assert_eq!(rfc3339(timestamp.into()), expected);
        }
        Ok(())
    }
}
