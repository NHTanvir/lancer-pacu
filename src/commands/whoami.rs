//! `whoami` command — call STS GetCallerIdentity.

use colored::Colorize;

use crate::module::AwsContext;

/// Call STS GetCallerIdentity and print the result.
pub async fn run(ctx: &AwsContext) {
    let client = aws_sdk_sts::Client::new(&ctx.sdk_config);

    match client.get_caller_identity().send().await {
        Ok(resp) => {
            let account = resp.account().unwrap_or("<unknown>");
            let user_id = resp.user_id().unwrap_or("<unknown>");
            let arn = resp.arn().unwrap_or("<unknown>");

            println!("{}", "─── STS GetCallerIdentity ────────────────────────".cyan());
            println!("  Account : {}", account.green().bold());
            println!("  UserID  : {}", user_id.yellow());
            println!("  ARN     : {}", arn.yellow());
            println!("{}", "──────────────────────────────────────────────────".cyan());
        }
        Err(e) => {
            eprintln!(
                "{} {}",
                "whoami failed:".red().bold(),
                e.to_string().red()
            );
            eprintln!(
                "{}",
                "Hint: configure AWS credentials (env vars, ~/.aws/credentials, or IAM role)."
                    .yellow()
            );
        }
    }
}
