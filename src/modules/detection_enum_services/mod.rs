//! detection__enum_services — enumerate active AWS detection and monitoring services.
//!
//! Category: ENUM. Services: ["CloudTrail", "GuardDuty", "Config", "EC2"].
//!
//! Read-only — always safe (no --armed needed).
//!
//! Calls:
//!   - cloudtrail:DescribeTrails        → list trails, S3 bucket, CloudWatch Logs group
//!   - cloudtrail:GetTrailStatus(ARN)   → IsLogging, LatestDeliveryTime
//!   - guardduty:ListDetectors          → detector IDs
//!   - guardduty:GetDetector(id)        → status, finding frequency
//!   - config:DescribeConfigurationRecorders (best-effort)
//!   - ec2:DescribeFlowLogs             → VPC Flow Logs configs
//!
//! Displays a summary table:
//!   Service     | Status    | Details
//!   CloudTrail  | ENABLED   | 2 trail(s), logging to s3://trail-bucket
//!   GuardDuty   | ENABLED   | detector abc123, findings every 6 hours
//!   Config      | UNKNOWN   | (access denied or not configured)
//!   VPC Flows   | DISABLED  | 0 flow log configs found

use colored::Colorize;
use comfy_table::{Cell, Table, presets::UTF8_FULL};

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, _args: &[&str]) -> anyhow::Result<()> {
    println!("{}", "detection__enum_services".cyan().bold());
    println!(
        "  {}\n",
        "Enumerating active AWS detection and monitoring services...".cyan()
    );

    // ── 1. CloudTrail ─────────────────────────────────────────────────────────
    let ct_status = enumerate_cloudtrail(ctx).await;

    // ── 2. GuardDuty ──────────────────────────────────────────────────────────
    let gd_status = enumerate_guardduty(ctx).await;

    // ── 3. Config (best-effort) ───────────────────────────────────────────────
    let config_status = enumerate_config(ctx).await;

    // ── 4. VPC Flow Logs ──────────────────────────────────────────────────────
    let vpc_status = enumerate_flow_logs(ctx).await;

    // ── Display summary table ──────────────────────────────────────────────────
    println!("\n{}", "--- Detection Services Summary ---".cyan().bold());

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        Cell::new("Service"),
        Cell::new("Status"),
        Cell::new("Details"),
    ]);

    let (ct_label, ct_detail) = ct_status;
    let (gd_label, gd_detail) = gd_status;
    let (cfg_label, cfg_detail) = config_status;
    let (vpc_label, vpc_detail) = vpc_status;

    table.add_row(vec![
        Cell::new("CloudTrail"),
        Cell::new(ct_label.clone()),
        Cell::new(ct_detail),
    ]);
    table.add_row(vec![
        Cell::new("GuardDuty"),
        Cell::new(gd_label.clone()),
        Cell::new(gd_detail),
    ]);
    table.add_row(vec![
        Cell::new("Config"),
        Cell::new(cfg_label.clone()),
        Cell::new(cfg_detail),
    ]);
    table.add_row(vec![
        Cell::new("VPC Flows"),
        Cell::new(vpc_label.clone()),
        Cell::new(vpc_detail),
    ]);

    println!("{table}");

    // Quick risk advisory
    let all_disabled = [&ct_label, &gd_label, &cfg_label, &vpc_label]
        .iter()
        .all(|s| s.as_str() == "DISABLED" || s.as_str() == "UNKNOWN");
    if all_disabled {
        println!(
            "{}",
            "  No detection services appear to be active — high evasion opportunity.".yellow()
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// CloudTrail enumeration
// ---------------------------------------------------------------------------

async fn enumerate_cloudtrail(ctx: &AwsContext) -> (String, String) {
    let ct = aws_sdk_cloudtrail::Client::new(&ctx.sdk_config);

    let desc = match ct.describe_trails().include_shadow_trails(false).send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                "UNKNOWN".to_owned(),
                format!("(access denied or error: {})", e),
            );
        }
    };

    let trails = desc.trail_list();
    if trails.is_empty() {
        return ("DISABLED".to_owned(), "0 trails found".to_owned());
    }

    let trail_count = trails.len();
    let mut logging_count = 0usize;
    let mut buckets: Vec<String> = Vec::new();
    let mut cw_groups: Vec<String> = Vec::new();

    for trail in trails {
        let arn = trail.trail_arn().unwrap_or("<unknown>");
        let bucket = trail.s3_bucket_name().unwrap_or("<unknown>");
        if !bucket.eq("<unknown>") {
            buckets.push(format!("s3://{}", bucket));
        }
        if let Some(cw) = trail.cloud_watch_logs_log_group_arn() {
            cw_groups.push(cw.to_owned());
        }

        // Check if logging is active
        if let Ok(status) = ct.get_trail_status().name(arn).send().await {
            if status.is_logging().unwrap_or(false) {
                logging_count += 1;
            }
        }
    }

    let status = if logging_count > 0 {
        "ENABLED".to_owned()
    } else {
        "DISABLED".to_owned()
    };

    let mut detail = format!(
        "{} trail(s), {} actively logging",
        trail_count, logging_count
    );
    if let Some(b) = buckets.first() {
        detail.push_str(&format!(", logging to {}", b));
    }
    if !cw_groups.is_empty() {
        detail.push_str(&format!(", CloudWatch: {} group(s)", cw_groups.len()));
    }

    (status, detail)
}

// ---------------------------------------------------------------------------
// GuardDuty enumeration
// ---------------------------------------------------------------------------

async fn enumerate_guardduty(ctx: &AwsContext) -> (String, String) {
    let gd = aws_sdk_guardduty::Client::new(&ctx.sdk_config);

    let list = match gd.list_detectors().send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                "UNKNOWN".to_owned(),
                format!("(access denied or error: {})", e),
            );
        }
    };

    let detector_ids = list.detector_ids();
    if detector_ids.is_empty() {
        return ("DISABLED".to_owned(), "0 detectors found".to_owned());
    }

    let mut details: Vec<String> = Vec::new();
    let mut enabled_count = 0usize;

    for detector_id in detector_ids {
        match gd.get_detector().detector_id(detector_id).send().await {
            Ok(det) => {
                let status_str = det
                    .status()
                    .map(|s| s.as_str().to_owned())
                    .unwrap_or_else(|| "UNKNOWN".to_owned());
                let freq = det
                    .finding_publishing_frequency()
                    .map(|f| f.as_str().to_owned())
                    .unwrap_or_else(|| "UNKNOWN".to_owned());
                if status_str.eq_ignore_ascii_case("ENABLED") {
                    enabled_count += 1;
                }
                details.push(format!(
                    "detector {} ({}, findings: {})",
                    detector_id, status_str, freq
                ));
            }
            Err(e) => {
                details.push(format!("detector {} (error: {})", detector_id, e));
            }
        }
    }

    let status = if enabled_count > 0 {
        "ENABLED".to_owned()
    } else {
        "DISABLED".to_owned()
    };

    (status, details.join("; "))
}

// ---------------------------------------------------------------------------
// AWS Config enumeration (best-effort)
// ---------------------------------------------------------------------------

async fn enumerate_config(ctx: &AwsContext) -> (String, String) {
    // aws-sdk-config is not included — use raw HTTP or skip gracefully.
    // We call describe_configuration_recorders via the EC2 client trick would be wrong;
    // instead we signal best-effort unavailability and note the user can check manually.
    // The aws-sdk-config crate is not a declared dependency, so we return UNKNOWN gracefully.
    let _ = ctx; // suppress unused warning

    // NOTE: aws-sdk-config is not a direct dependency. Returning best-effort status.
    (
        "UNKNOWN".to_owned(),
        "(aws-sdk-config not linked; check manually with: aws configservice describe-configuration-recorders)".to_owned(),
    )
}

// ---------------------------------------------------------------------------
// VPC Flow Logs enumeration
// ---------------------------------------------------------------------------

async fn enumerate_flow_logs(ctx: &AwsContext) -> (String, String) {
    let ec2 = aws_sdk_ec2::Client::new(&ctx.sdk_config);

    let resp = match ec2.describe_flow_logs().send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                "UNKNOWN".to_owned(),
                format!("(access denied or error: {})", e),
            );
        }
    };

    let flow_logs = resp.flow_logs();
    if flow_logs.is_empty() {
        return ("DISABLED".to_owned(), "0 flow log configs found".to_owned());
    }

    let active_count = flow_logs
        .iter()
        .filter(|fl| {
            fl.flow_log_status()
                .map(|s| s.eq_ignore_ascii_case("ACTIVE"))
                .unwrap_or(false)
        })
        .count();

    let detail = format!(
        "{} flow log config(s), {} active",
        flow_logs.len(),
        active_count
    );

    let status = if active_count > 0 {
        "ENABLED".to_owned()
    } else {
        "DISABLED".to_owned()
    };

    (status, detail)
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "detection__enum_services",
            author: "lancer-pacu",
            category: "ENUM",
            one_liner: "Enumerate active detection services: CloudTrail, GuardDuty, Config, VPC Flow Logs.",
            services: &["CloudTrail", "GuardDuty", "Config", "EC2"],
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
            .any(|m| m.info.name == "detection__enum_services");
        assert!(found, "detection__enum_services not found in inventory");
    }

    #[test]
    fn module_category_is_enum() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "detection__enum_services")
            .expect("detection__enum_services not found");
        assert_eq!(m.info.category, "ENUM");
    }

    #[test]
    fn module_services_include_cloudtrail_and_guardduty() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "detection__enum_services")
            .expect("detection__enum_services not found");
        assert!(
            m.info.services.contains(&"CloudTrail"),
            "services should include CloudTrail"
        );
        assert!(
            m.info.services.contains(&"GuardDuty"),
            "services should include GuardDuty"
        );
    }
}
