//! aws__enum_account — enumerate the current AWS account information.
//!
//! Calls:
//!   - sts:GetCallerIdentity  — account ID, user ID, ARN
//!   - iam:GetAccountSummary  — account-level summary statistics
//!
//! Results are displayed in comfy-table and cached to the session DB
//! under the "extra" column as a JSON object.

use anyhow::Context as _;
use colored::Colorize;
use comfy_table::{Cell, Table, presets::UTF8_FULL};
use serde_json::json;

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, _args: &[&str]) -> anyhow::Result<()> {
    // ── 1. STS GetCallerIdentity ───────────────────────────────────────────
    let sts = aws_sdk_sts::Client::new(&ctx.sdk_config);
    let identity = sts
        .get_caller_identity()
        .send()
        .await
        .context("sts:GetCallerIdentity failed")?;

    let account_id = identity.account().unwrap_or("<unknown>").to_owned();
    let user_id    = identity.user_id().unwrap_or("<unknown>").to_owned();
    let arn        = identity.arn().unwrap_or("<unknown>").to_owned();

    println!("{}", "─── STS GetCallerIdentity ───────────────────────────────".cyan());
    println!("  Account ID : {}", account_id.green().bold());
    println!("  User ID    : {}", user_id.yellow());
    println!("  ARN        : {}", arn.yellow());

    // ── 2. IAM GetAccountSummary ───────────────────────────────────────────
    let iam = aws_sdk_iam::Client::new(&ctx.sdk_config);
    let summary_resp = iam
        .get_account_summary()
        .send()
        .await
        .context("iam:GetAccountSummary failed")?;

    // summary_map() returns Option<&HashMap<SummaryKeyType, i32>>
    let summary_map = summary_resp
        .summary_map()
        .cloned()
        .unwrap_or_default();

    let mut summary_table = Table::new();
    summary_table.load_preset(UTF8_FULL);
    summary_table.set_header(vec!["Key", "Value"]);

    // Build a plain JSON object from the summary map so we can cache it.
    let mut summary_json = serde_json::Map::new();

    // Sort keys for consistent display.
    let mut keys: Vec<String> = summary_map
        .keys()
        .map(|k| k.as_str().to_owned())
        .collect();
    keys.sort();

    for key in &keys {
        let val = summary_map
            .iter()
            .find(|(k, _)| k.as_str() == key.as_str())
            .map(|(_, v)| *v)
            .unwrap_or(0);

        summary_table.add_row(vec![
            Cell::new(key),
            Cell::new(val.to_string()),
        ]);
        summary_json.insert(key.clone(), json!(val));
    }

    println!("\n{}", "─── IAM GetAccountSummary ───────────────────────────────".cyan());
    println!("{summary_table}");

    // ── 3. Cache to session DB ─────────────────────────────────────────────
    if let Some(pool) = &ctx.db_pool {
        // Load the active session so we have its id.
        match crate::db::get_active_session(pool).await {
            Ok(Some(sess)) => {
                let extra = json!({
                    "account_id":      account_id,
                    "user_id":         user_id,
                    "arn":             arn,
                    "account_summary": summary_json,
                });
                if let Err(e) = crate::db::update_session_data(
                    pool,
                    sess.id,
                    "extra",
                    &extra.to_string(),
                )
                .await
                {
                    eprintln!("{} {e}", "Warning: could not cache account data:".yellow());
                } else {
                    println!("{}", "Account data cached to session DB (key: extra).".green());
                }
            }
            Ok(None) => {
                println!("{}", "No active session — skipping DB cache.".yellow());
            }
            Err(e) => {
                eprintln!("{} {e}", "Warning: DB error:".yellow());
            }
        }
    } else {
        println!("{}", "Session DB unavailable — skipping cache.".yellow());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "aws__enum_account",
            author: "lancer-pacu",
            category: "ENUM",
            one_liner: "Enumerate the current AWS account information.",
            services: &["STS", "IAM"],
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

    /// The module must appear in the inventory after compilation.
    #[test]
    fn module_registered_in_inventory() {
        let found = inventory::iter::<Module>
            .into_iter()
            .any(|m| m.info.name == "aws__enum_account");
        assert!(found, "aws__enum_account not found in inventory");
    }
}
