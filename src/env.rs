//! Canonical environment-variable resolution and small process-level
//! helpers for guard.
//!
//! Configuration variables use the `GUARD_` prefix.

/// Resolve a guard configuration variable by its suffix (the part after the
/// `GUARD_` prefix). Returns `None` if `GUARD_<SUFFIX>` is not set.
pub fn guard_env(suffix: &str) -> Option<String> {
    std::env::var(format!("GUARD_{}", suffix)).ok()
}

/// Current wall-clock time as whole seconds since the Unix epoch. A clock
/// set before the epoch reads as 0 rather than failing.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Render Unix seconds as an ISO-8601 UTC instant. Guard states times in UTC
/// everywhere a human reads one, so this is the single spelling.
pub fn unix_seconds_to_utc(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let seconds = ts % 86_400;
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Days since the Unix epoch to a proleptic Gregorian civil date, by Howard
/// Hinnant's `civil_from_days`.
fn civil_from_days(days_since_epoch: i64) -> (i64, u64, u64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month as u64, day as u64)
}
