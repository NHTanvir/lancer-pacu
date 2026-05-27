//! iam__get_credential_report — generate and display the IAM credential report.
//!
//! Calls:
//!   1. iam:GenerateCredentialReport — trigger generation (polls until COMPLETE)
//!   2. iam:GetCredentialReport      — fetch base64-encoded CSV, decode, display

use anyhow::Context as _;
use colored::Colorize;
use comfy_table::{Cell, Table, presets::UTF8_FULL};

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// CSV parsing helpers (pub for test access)
// ---------------------------------------------------------------------------

/// Parse a credential-report CSV string into a header row and data rows.
///
/// Returns `(headers, rows)` where every inner `Vec<String>` has the same
/// length as `headers`.
pub fn parse_credential_report_csv(csv: &str) -> (Vec<String>, Vec<Vec<String>>) {
    let mut lines = csv.lines();

    // First line = headers
    let headers: Vec<String> = lines
        .next()
        .unwrap_or("")
        .split(',')
        .map(|s| s.to_owned())
        .collect();

    let rows: Vec<Vec<String>> = lines
        .map(|line| line.split(',').map(|s| s.to_owned()).collect())
        .collect();

    (headers, rows)
}

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, _args: &[&str]) -> anyhow::Result<()> {
    let iam = aws_sdk_iam::Client::new(&ctx.sdk_config);

    // ── 1. Generate the credential report (poll until COMPLETE) ───────────
    println!("{}", "Requesting IAM credential report…".cyan());

    let max_attempts = 15; // 15 × 2 s = 30 s max
    let mut complete = false;

    for attempt in 1..=max_attempts {
        let resp = iam
            .generate_credential_report()
            .send()
            .await
            .context("iam:GenerateCredentialReport failed")?;

        let state = resp.state().map(|s| s.as_str()).unwrap_or("UNKNOWN");

        if state == "COMPLETE" {
            complete = true;
            break;
        }

        println!(
            "  Attempt {}/{}: state = {} — waiting 2 s…",
            attempt, max_attempts, state
        );
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    if !complete {
        anyhow::bail!("Credential report did not complete within 30 seconds.");
    }

    // ── 2. Retrieve the report ─────────────────────────────────────────────
    let report_resp = iam
        .get_credential_report()
        .send()
        .await
        .context("iam:GetCredentialReport failed")?;

    let raw_bytes = report_resp
        .content()
        .ok_or_else(|| anyhow::anyhow!("GetCredentialReport returned empty content"))?;

    // The SDK returns a `Blob`; decode it from base64 via the underlying bytes.
    // `aws_sdk_iam::primitives::Blob` implements `as_ref() -> &[u8]` which
    // already gives the decoded bytes (the SDK handles base64 transport for us).
    let csv_bytes: &[u8] = raw_bytes.as_ref();

    // Attempt to interpret as UTF-8; if that fails fall back to lossy conversion.
    let csv_text = std::str::from_utf8(csv_bytes)
        .map(|s| s.to_owned())
        .unwrap_or_else(|_| String::from_utf8_lossy(csv_bytes).into_owned());

    // ── 3. Parse and display ───────────────────────────────────────────────
    let (headers, rows) = parse_credential_report_csv(&csv_text);

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(headers.iter().map(|h| Cell::new(h)));

    for row in &rows {
        table.add_row(row.iter().map(|c| Cell::new(c)));
    }

    println!("\n{}", "─── IAM Credential Report ───────────────────────────────".cyan());
    println!("{table}");
    println!(
        "{}",
        format!("Report contains {} account(s).", rows.len())
            .green()
            .bold()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "iam__get_credential_report",
            author: "lancer-pacu",
            category: "ENUM",
            one_liner: "Generate and display the IAM credential report.",
            services: &["IAM"],
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

    const SAMPLE_CSV: &str = "\
user,arn,user_creation_time,password_enabled,password_last_used,\
password_last_rotated,password_next_rotation,mfa_active,\
access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,\
access_key_1_last_used_region,access_key_1_last_used_service,\
access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,\
access_key_2_last_used_region,access_key_2_last_used_service,\
cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,\
not_supported,2024-01-15T10:30:00+00:00,not_supported,not_applicable,\
false,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
alice,arn:aws:iam::123456789012:user/alice,2021-06-01T08:00:00+00:00,\
true,2024-01-10T09:00:00+00:00,2023-06-01T08:00:00+00:00,\
2024-06-01T08:00:00+00:00,true,true,2023-06-01T08:00:00+00:00,\
2024-01-10T09:00:00+00:00,us-east-1,s3,false,N/A,N/A,N/A,N/A,\
false,N/A,false,N/A";

    /// parse_credential_report_csv correctly splits headers and rows.
    #[test]
    fn csv_parse_headers_count() {
        let (headers, rows) = parse_credential_report_csv(SAMPLE_CSV);
        assert_eq!(headers.len(), 22, "expected 22 CSV columns");
        assert_eq!(rows.len(), 2, "expected 2 data rows");
    }

    /// First header should be "user".
    #[test]
    fn csv_parse_first_header_is_user() {
        let (headers, _) = parse_credential_report_csv(SAMPLE_CSV);
        assert_eq!(headers[0], "user");
    }

    /// First data row first column should be "<root_account>".
    #[test]
    fn csv_parse_root_account_row() {
        let (_, rows) = parse_credential_report_csv(SAMPLE_CSV);
        assert_eq!(rows[0][0], "<root_account>");
    }

    /// Second row user field should be "alice".
    #[test]
    fn csv_parse_alice_row() {
        let (_, rows) = parse_credential_report_csv(SAMPLE_CSV);
        assert_eq!(rows[1][0], "alice");
    }

    /// Empty CSV produces empty headers and no rows.
    #[test]
    fn csv_parse_empty_string() {
        let (headers, rows) = parse_credential_report_csv("");
        // An empty string produces one empty header element from split(',')
        assert_eq!(headers, vec!["".to_owned()]);
        assert!(rows.is_empty());
    }

    /// Module is registered in the inventory.
    #[test]
    fn module_registered_in_inventory() {
        let found = inventory::iter::<Module>
            .into_iter()
            .any(|m| m.info.name == "iam__get_credential_report");
        assert!(found, "iam__get_credential_report not found in inventory");
    }

    /// The total module count is at least 3 (our three new modules).
    #[test]
    fn inventory_has_at_least_three_modules() {
        let count = inventory::iter::<Module>.into_iter().count();
        assert!(
            count >= 3,
            "expected at least 3 modules in inventory, found {count}"
        );
    }
}
