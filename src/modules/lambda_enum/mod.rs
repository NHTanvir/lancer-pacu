//! lambda__enum — enumerate Lambda functions, layers, and event source mappings.
//!
//! Calls (paginated):
//!   - lambda:ListFunctions            → function summaries
//!   - lambda:ListEventSourceMappings  → event source mappings
//!   - lambda:ListLayers               → Lambda layers
//!
//! Results are cached to the session DB as `lambda_functions` and a summary
//! table is printed.

use anyhow::Context as _;
use colored::Colorize;
use comfy_table::{Cell, Table, presets::UTF8_FULL};
use serde::{Deserialize, Serialize};

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Serialisable structs
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LambdaFunction {
    pub name: String,
    pub runtime: String,
    pub handler: String,
    pub role: String,
    pub memory_mb: i32,
    pub timeout_s: i32,
    pub last_modified: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LambdaEventSourceMapping {
    pub uuid: String,
    pub function_arn: String,
    pub event_source_arn: String,
    pub state: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LambdaLayer {
    pub name: String,
    pub version: i64,
    pub compatible_runtimes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, _args: &[&str]) -> anyhow::Result<()> {
    let lambda = aws_sdk_lambda::Client::new(&ctx.sdk_config);

    // ── 1. ListFunctions ──────────────────────────────────────────────────
    println!("{}", "Enumerating Lambda functions...".cyan());
    let mut functions: Vec<LambdaFunction> = Vec::new();
    {
        let mut marker: Option<String> = None;
        loop {
            let mut req = lambda.list_functions();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let page = req
                .send()
                .await
                .context("lambda:ListFunctions failed")?;

            for f in page.functions() {
                functions.push(LambdaFunction {
                    name: f.function_name().unwrap_or("<unknown>").to_owned(),
                    runtime: f
                        .runtime()
                        .map(|r| r.as_str().to_owned())
                        .unwrap_or_else(|| "<unknown>".to_owned()),
                    handler: f.handler().unwrap_or("<unknown>").to_owned(),
                    role: f.role().unwrap_or("<unknown>").to_owned(),
                    memory_mb: f.memory_size().unwrap_or(0),
                    timeout_s: f.timeout().unwrap_or(0),
                    last_modified: f.last_modified().unwrap_or("<unknown>").to_owned(),
                });
            }

            match page.next_marker() {
                Some(m) => marker = Some(m.to_owned()),
                None => break,
            }
        }
    }

    // ── 2. ListEventSourceMappings ────────────────────────────────────────
    println!("{}", "Enumerating Lambda event source mappings...".cyan());
    let mut event_mappings: Vec<LambdaEventSourceMapping> = Vec::new();
    {
        let mut marker: Option<String> = None;
        loop {
            let mut req = lambda.list_event_source_mappings();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let page = req
                .send()
                .await
                .context("lambda:ListEventSourceMappings failed")?;

            for esm in page.event_source_mappings() {
                event_mappings.push(LambdaEventSourceMapping {
                    uuid: esm.uuid().unwrap_or("<unknown>").to_owned(),
                    function_arn: esm.function_arn().unwrap_or("<unknown>").to_owned(),
                    event_source_arn: esm.event_source_arn().unwrap_or("<unknown>").to_owned(),
                    state: esm.state().unwrap_or("<unknown>").to_owned(),
                });
            }

            match page.next_marker() {
                Some(m) => marker = Some(m.to_owned()),
                None => break,
            }
        }
    }

    // ── 3. ListLayers ─────────────────────────────────────────────────────
    println!("{}", "Enumerating Lambda layers...".cyan());
    let mut layers: Vec<LambdaLayer> = Vec::new();
    {
        let mut marker: Option<String> = None;
        loop {
            let mut req = lambda.list_layers();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let page = req
                .send()
                .await
                .context("lambda:ListLayers failed")?;

            for layer in page.layers() {
                let latest = layer.latest_matching_version();
                let version = latest.map(|v| v.version()).unwrap_or(0);
                let runtimes: Vec<String> = latest
                    .map(|v| {
                        v.compatible_runtimes()
                            .iter()
                            .map(|r| r.as_str().to_owned())
                            .collect()
                    })
                    .unwrap_or_default();

                layers.push(LambdaLayer {
                    name: layer.layer_name().unwrap_or("<unknown>").to_owned(),
                    version,
                    compatible_runtimes: runtimes,
                });
            }

            match page.next_marker() {
                Some(m) => marker = Some(m.to_owned()),
                None => break,
            }
        }
    }

    // ── Display summary ────────────────────────────────────────────────────
    println!(
        "\n{}",
        "--- Lambda Enumeration Summary ---".cyan()
    );
    println!(
        "  Enumerated {} functions, {} event source mappings, {} layers",
        functions.len().to_string().green().bold(),
        event_mappings.len().to_string().green().bold(),
        layers.len().to_string().green().bold(),
    );

    if !functions.is_empty() {
        let mut t = Table::new();
        t.load_preset(UTF8_FULL);
        t.set_header(vec![
            "Name",
            "Runtime",
            "Role",
            "Memory (MB)",
            "Timeout (s)",
            "Last Modified",
        ]);
        for f in functions.iter().take(20) {
            // Truncate role ARN for display
            let role_display = if f.role.len() > 40 {
                format!("...{}", &f.role[f.role.len() - 37..])
            } else {
                f.role.clone()
            };
            t.add_row(vec![
                Cell::new(&f.name),
                Cell::new(&f.runtime),
                Cell::new(role_display),
                Cell::new(f.memory_mb.to_string()),
                Cell::new(f.timeout_s.to_string()),
                Cell::new(&f.last_modified),
            ]);
        }
        if functions.len() > 20 {
            println!("(showing first 20 of {})", functions.len());
        }
        println!("{t}");
    }

    // ── Cache to session DB ────────────────────────────────────────────────
    if let Some(pool) = &ctx.db_pool {
        match crate::db::get_active_session(pool).await {
            Ok(Some(sess)) => {
                match serde_json::to_string(&functions) {
                    Ok(json) => {
                        if let Err(e) =
                            crate::db::update_session_data(pool, sess.id, "lambda_functions", &json)
                                .await
                        {
                            eprintln!(
                                "{} lambda_functions: {e}",
                                "Warning: could not cache".yellow()
                            );
                        } else {
                            println!("{}", "Lambda functions cached to session DB.".green());
                        }
                    }
                    Err(e) => eprintln!(
                        "{} lambda_functions: {e}",
                        "Warning: serialisation failed for".yellow()
                    ),
                }
            }
            Ok(None) => println!("{}", "No active session — skipping DB cache.".yellow()),
            Err(e) => eprintln!("{} {e}", "Warning: DB error:".yellow()),
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
            name: "lambda__enum",
            author: "lancer-pacu",
            category: "ENUM",
            one_liner: "Enumerate Lambda functions, layers, and event source mappings.",
            services: &["Lambda"],
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
            .any(|m| m.info.name == "lambda__enum");
        assert!(found, "lambda__enum not found in inventory");
    }

    #[test]
    fn lambda_function_serde_round_trip() {
        let f = LambdaFunction {
            name: "my-function".to_owned(),
            runtime: "python3.11".to_owned(),
            handler: "index.handler".to_owned(),
            role: "arn:aws:iam::123456789012:role/lambda-role".to_owned(),
            memory_mb: 128,
            timeout_s: 30,
            last_modified: "2024-01-01T00:00:00.000+0000".to_owned(),
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: LambdaFunction = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "my-function");
        assert_eq!(back.runtime, "python3.11");
        assert_eq!(back.memory_mb, 128);
    }

    #[test]
    fn lambda_layer_serde_round_trip() {
        let l = LambdaLayer {
            name: "my-layer".to_owned(),
            version: 3,
            compatible_runtimes: vec!["python3.11".to_owned(), "python3.10".to_owned()],
        };
        let json = serde_json::to_string(&l).unwrap();
        let back: LambdaLayer = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "my-layer");
        assert_eq!(back.version, 3);
        assert_eq!(back.compatible_runtimes.len(), 2);
    }
}
