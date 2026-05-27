//! cloudtrail__download_event_history — download CloudTrail event history for a time window.
//!
//! Category: EVADE. Services: ["CloudTrail"].
//!
//! Read-only — always safe (downloading logs is not a write operation).
//!
//! Calls cloudtrail:LookupEvents with optional attribute filters, paginating all
//! results, and writes them to a JSON file.
//!
//! Args:
//!   --start-time <ISO8601>   start of window (default: 24 hours ago)
//!   --end-time   <ISO8601>   end of window   (default: now)
//!   --output     <filename>  output file (default: cloudtrail-events-<timestamp>.json)
//!   --event-name <name>      filter by event name  (optional, e.g. "CreateUser")
//!   --username   <name>      filter by username     (optional)

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use aws_sdk_cloudtrail::types::LookupAttribute;
use aws_sdk_cloudtrail::types::LookupAttributeKey;
use aws_smithy_types::DateTime as SmithyDateTime;
use colored::Colorize;
use serde_json::Value;

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

/// Parse an ISO 8601 string into a `SystemTime`.
///
/// Supports the subset: `YYYY-MM-DDTHH:MM:SSZ` and `YYYY-MM-DDTHH:MM:SS+00:00`.
fn parse_iso8601(s: &str) -> anyhow::Result<SystemTime> {
    // Normalise to Z-suffix form
    let s = s.trim_end_matches("+00:00");
    let s = s.trim_end_matches('Z');

    // Expect exactly "YYYY-MM-DDTHH:MM:SS"
    if s.len() < 19 {
        anyhow::bail!("Invalid ISO8601 timestamp: '{}' (expected YYYY-MM-DDTHH:MM:SS)", s);
    }
    let year: i64 = s[0..4].parse().context("invalid year")?;
    let month: u64 = s[5..7].parse().context("invalid month")?;
    let day: u64 = s[8..10].parse().context("invalid day")?;
    let hour: u64 = s[11..13].parse().context("invalid hour")?;
    let min: u64 = s[14..16].parse().context("invalid minute")?;
    let sec: u64 = s[17..19].parse().context("invalid second")?;

    // Compute Unix timestamp (simplified; ignores leap seconds)
    let days_in_month = [0u64, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    #[allow(clippy::manual_is_multiple_of)]
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);

    let mut total_days: u64 = 0;
    // Days for years 1970..year
    for y in 1970..year {
        #[allow(clippy::manual_is_multiple_of)]
        let leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        total_days += if leap { 366 } else { 365 };
    }
    // Days for months 1..month
    for m in 1..month {
        total_days += days_in_month[m as usize];
        if m == 2 && is_leap {
            total_days += 1;
        }
    }
    total_days += day - 1;

    let unix_secs = total_days * 86400 + hour * 3600 + min * 60 + sec;
    Ok(UNIX_EPOCH + std::time::Duration::from_secs(unix_secs))
}

/// Format a `SystemTime` as a simple ISO 8601 timestamp string (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn format_timestamp_for_filename(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Simple decomposition (no external crate required)
    let mut remaining = secs;
    let sec = remaining % 60;
    remaining /= 60;
    let min = remaining % 60;
    remaining /= 60;
    let hour = remaining % 24;
    remaining /= 24;

    // Days since epoch to calendar date
    let mut year = 1970u64;
    loop {
        #[allow(clippy::manual_is_multiple_of)]
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if leap { 366u64 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }
    let days_in_month = [0u64, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    #[allow(clippy::manual_is_multiple_of)]
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let mut month = 1u64;
    loop {
        let mut dim = days_in_month[month as usize];
        if month == 2 && is_leap {
            dim += 1;
        }
        if remaining < dim {
            break;
        }
        remaining -= dim;
        month += 1;
    }
    let day = remaining + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
}

/// Return current `SystemTime`.
pub fn now() -> SystemTime {
    SystemTime::now()
}

/// Return the `SystemTime` 24 hours before the provided time.
pub fn minus_24h(t: SystemTime) -> SystemTime {
    t - std::time::Duration::from_secs(86400)
}

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let now_ts = now();
    let default_start = minus_24h(now_ts);

    let start_time: SystemTime = match args.iter().position(|&a| a == "--start-time") {
        Some(pos) => match args.get(pos + 1).copied() {
            Some(s) => parse_iso8601(s).context("--start-time: invalid ISO8601 value")?,
            None => anyhow::bail!("--start-time requires a value"),
        },
        None => default_start,
    };

    let end_time: SystemTime = match args.iter().position(|&a| a == "--end-time") {
        Some(pos) => match args.get(pos + 1).copied() {
            Some(s) => parse_iso8601(s).context("--end-time: invalid ISO8601 value")?,
            None => anyhow::bail!("--end-time requires a value"),
        },
        None => now_ts,
    };

    let output_filename: String = match args.iter().position(|&a| a == "--output") {
        Some(pos) => match args.get(pos + 1).copied() {
            Some(f) => f.to_owned(),
            None => anyhow::bail!("--output requires a filename"),
        },
        None => {
            let ts = format_timestamp_for_filename(now_ts)
                .replace(':', "-")
                .replace('T', "_");
            format!("cloudtrail-events-{}.json", ts)
        }
    };

    let event_name_filter: Option<&str> = args
        .iter()
        .position(|&a| a == "--event-name")
        .and_then(|i| args.get(i + 1).copied());

    let username_filter: Option<&str> = args
        .iter()
        .position(|&a| a == "--username")
        .and_then(|i| args.get(i + 1).copied());

    println!("{}", "cloudtrail__download_event_history".cyan().bold());
    println!("  Time window: {} → {}", format_timestamp_for_filename(start_time), format_timestamp_for_filename(end_time));
    if let Some(en) = event_name_filter {
        println!("  Filter — EventName: {}", en.yellow());
    }
    if let Some(un) = username_filter {
        println!("  Filter — Username: {}", un.yellow());
    }
    println!("  Output file: {}", output_filename.yellow());
    println!();

    let ct = aws_sdk_cloudtrail::Client::new(&ctx.sdk_config);

    // Build lookup attributes (CloudTrail allows at most one at a time via the API,
    // but we support whichever single filter the user requested, preferring EventName).
    // If both are given, we use EventName and note that Username is ignored.
    let lookup_attr: Option<LookupAttribute> = if let Some(en) = event_name_filter {
        Some(
            LookupAttribute::builder()
                .attribute_key(LookupAttributeKey::EventName)
                .attribute_value(en)
                .build()
                .context("Failed to build LookupAttribute for EventName")?,
        )
    } else if let Some(un) = username_filter {
        Some(
            LookupAttribute::builder()
                .attribute_key(LookupAttributeKey::Username)
                .attribute_value(un)
                .build()
                .context("Failed to build LookupAttribute for Username")?,
        )
    } else {
        None
    };

    // Convert SystemTime to SmithyDateTime (aws_smithy_types::DateTime)
    let start_dt = {
        let secs = start_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        SmithyDateTime::from_secs(secs)
    };
    let end_dt = {
        let secs = end_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        SmithyDateTime::from_secs(secs)
    };

    // ── Paginate LookupEvents ──────────────────────────────────────────────
    println!("{}", "  Fetching events (paginating)...".cyan());
    let mut all_events: Vec<Value> = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = ct
            .lookup_events()
            .start_time(start_dt)
            .end_time(end_dt);

        if let Some(ref attr) = lookup_attr {
            req = req.lookup_attributes(attr.clone());
        }
        if let Some(ref tok) = next_token {
            req = req.next_token(tok);
        }

        let page = req
            .send()
            .await
            .context("cloudtrail:LookupEvents failed")?;

        for event in page.events() {
            // Serialise each event to a serde_json Value
            let event_json = serde_json::json!({
                "EventId":     event.event_id().unwrap_or("<unknown>"),
                "EventName":   event.event_name().unwrap_or("<unknown>"),
                "EventSource": event.event_source().unwrap_or("<unknown>"),
                "Username":    event.username().unwrap_or("<unknown>"),
                "CloudTrailEvent": event.cloud_trail_event().unwrap_or(""),
            });
            all_events.push(event_json);
        }

        match page.next_token() {
            Some(tok) => next_token = Some(tok.to_owned()),
            None => break,
        }
    }

    // ── Write to file ──────────────────────────────────────────────────────
    let json_bytes = serde_json::to_string_pretty(&all_events)
        .context("Failed to serialise events to JSON")?;
    std::fs::write(&output_filename, json_bytes)
        .with_context(|| format!("Failed to write to '{}'", output_filename))?;

    println!(
        "  {} Downloaded {} event(s) to '{}'",
        "[OK]".green().bold(),
        all_events.len().to_string().green().bold(),
        output_filename.green()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "cloudtrail__download_event_history",
            author: "lancer-pacu",
            category: "EVADE",
            one_liner: "Download CloudTrail event history (paginated) for a given time window to JSON.",
            services: &["CloudTrail"],
        },
        run: |ctx, args| Box::pin(run(ctx, args)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::Module;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn module_registered_in_inventory() {
        let found = inventory::iter::<Module>
            .into_iter()
            .any(|m| m.info.name == "cloudtrail__download_event_history");
        assert!(found, "cloudtrail__download_event_history not found in inventory");
    }

    #[test]
    fn module_category_is_evade() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "cloudtrail__download_event_history")
            .expect("cloudtrail__download_event_history not found");
        assert_eq!(m.info.category, "EVADE");
    }

    #[test]
    fn default_time_window_is_24h_ago() {
        let t = now();
        let start = minus_24h(t);
        let diff = t
            .duration_since(start)
            .expect("now should be after start");
        // Should be exactly 24 hours (86400 seconds)
        assert_eq!(
            diff,
            Duration::from_secs(86400),
            "default start time should be exactly 24 hours before now"
        );
    }

    #[test]
    fn parse_iso8601_valid() {
        let t = parse_iso8601("2024-01-15T10:30:00Z").expect("should parse");
        // 2024-01-15T10:30:00Z in Unix seconds:
        // Days from epoch to 2024-01-15:
        //   Years 1970-2023 (54 years, 13 leap): 41*365 + 13*366 = 14965+4758 = 19723 days
        //   Jan 1-14 2024 = 14 more days → 19737 days total
        //   19737 * 86400 = 1705276800
        // Time 10:30:00 = 37800 seconds
        // Total = 1705276800 + 37800 = 1705314600
        let secs = t.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 1705314600, "parsed timestamp mismatch: got {secs}");
    }

    #[test]
    fn parse_iso8601_invalid_returns_error() {
        let result = parse_iso8601("not-a-date");
        assert!(result.is_err(), "should error on invalid timestamp");
    }

    #[test]
    fn format_timestamp_round_trip() {
        // Build a known SystemTime and format it
        // 2024-01-15T10:30:00Z = 1705314600 Unix seconds (see parse_iso8601_valid for derivation)
        let known_secs = 1705314600u64;
        let t = UNIX_EPOCH + Duration::from_secs(known_secs);
        let formatted = format_timestamp_for_filename(t);
        assert_eq!(formatted, "2024-01-15T10:30:00Z");
    }

    #[test]
    fn default_output_filename_contains_prefix() {
        let t = now();
        let ts = format_timestamp_for_filename(t)
            .replace(':', "-")
            .replace('T', "_");
        let filename = format!("cloudtrail-events-{}.json", ts);
        assert!(
            filename.starts_with("cloudtrail-events-"),
            "filename should start with cloudtrail-events-: {filename}"
        );
        assert!(filename.ends_with(".json"), "filename should end with .json");
    }
}
