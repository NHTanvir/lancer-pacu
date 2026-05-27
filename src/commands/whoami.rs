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

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn whoami_returns_result_not_panic() {
        // Create an AwsContext with fake AWS credentials.
        // This will fail with an AWS auth error (as expected), but the function
        // must not panic — it should handle the error gracefully.
        let ctx = AwsContext::from_keys(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
            Some("us-east-1"),
            true, // dry_run = true
        )
        .await;

        // Call run() — it should return without panicking.
        // The output goes to stdout/stderr, but we just verify no panic occurs.
        run(&ctx).await;
    }
}
