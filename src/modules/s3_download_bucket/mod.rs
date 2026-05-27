//! s3__download_bucket — list and optionally download objects from an S3 bucket.
//!
//! Args:
//!   --bucket <bucket_name>   target bucket (required)
//!   --prefix <prefix>        S3 key prefix filter (optional)
//!   --output-dir <dir>       local directory to save files (default: ./s3-dump/<bucket>/)
//!   --max-objects <n>        max objects to download (default: 100)
//!
//! Dry-run mode (default): lists objects that *would* be downloaded. No files written.
//! Armed mode: downloads each object up to --max-objects.

use anyhow::Context as _;
use colored::Colorize;
use comfy_table::{Cell, Table, presets::UTF8_FULL};
use serde::{Deserialize, Serialize};

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Serialisable object metadata struct
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct S3ObjectMeta {
    pub key: String,
    pub size_bytes: i64,
    pub last_modified: Option<String>,
    pub storage_class: Option<String>,
}

// ---------------------------------------------------------------------------
// Helper: format DateTime from S3 primitives
// ---------------------------------------------------------------------------

fn fmt_s3_dt(dt: &aws_sdk_s3::primitives::DateTime) -> String {
    dt.fmt(aws_sdk_s3::primitives::DateTimeFormat::DateTime)
        .unwrap_or_else(|_| "<invalid-date>".to_owned())
}

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let bucket: &str = {
        let pos = args.iter().position(|&a| a == "--bucket");
        match pos.and_then(|i| args.get(i + 1).copied()) {
            Some(b) => b,
            None => anyhow::bail!("--bucket <bucket_name> is required"),
        }
    };

    let prefix: Option<&str> = {
        let pos = args.iter().position(|&a| a == "--prefix");
        pos.and_then(|i| args.get(i + 1).copied())
    };

    let output_dir: std::path::PathBuf = {
        let pos = args.iter().position(|&a| a == "--output-dir");
        match pos.and_then(|i| args.get(i + 1).copied()) {
            Some(d) => std::path::PathBuf::from(d),
            None => std::path::PathBuf::from(format!("./s3-dump/{bucket}/")),
        }
    };

    let max_objects: usize = {
        let pos = args.iter().position(|&a| a == "--max-objects");
        match pos.and_then(|i| args.get(i + 1).copied()) {
            Some(n) => n.parse::<usize>().unwrap_or(100),
            None => 100,
        }
    };

    let s3 = aws_sdk_s3::Client::new(&ctx.sdk_config);

    // ── List objects ───────────────────────────────────────────────────────
    println!(
        "{}",
        format!("Listing objects in s3://{bucket}/{}…", prefix.unwrap_or("")).cyan()
    );

    let mut objects: Vec<S3ObjectMeta> = Vec::new();
    let mut continuation_token: Option<String> = None;

    loop {
        let mut req = s3.list_objects_v2().bucket(bucket);
        if let Some(pfx) = prefix {
            req = req.prefix(pfx);
        }
        if let Some(ref tok) = continuation_token {
            req = req.continuation_token(tok.clone());
        }

        let page = req.send().await.context("s3:ListObjectsV2 failed")?;

        for obj in page.contents() {
            let key = obj.key().unwrap_or("<unknown>").to_owned();
            let size = obj.size().unwrap_or(0);
            let last_mod = obj.last_modified().map(fmt_s3_dt);
            let sc = obj
                .storage_class()
                .map(|s| s.as_str().to_owned());

            objects.push(S3ObjectMeta {
                key,
                size_bytes: size,
                last_modified: last_mod,
                storage_class: sc,
            });

            if objects.len() >= max_objects {
                break;
            }
        }

        if objects.len() >= max_objects || !page.is_truncated().unwrap_or(false) {
            break;
        }

        continuation_token = page.next_continuation_token().map(|s| s.to_owned());
    }

    // ── Display object list ────────────────────────────────────────────────
    let mut t = Table::new();
    t.load_preset(UTF8_FULL);
    t.set_header(vec!["Key", "Size (bytes)", "Last Modified", "Storage Class"]);
    for obj in objects.iter().take(20) {
        t.add_row(vec![
            Cell::new(&obj.key),
            Cell::new(obj.size_bytes.to_string()),
            Cell::new(obj.last_modified.as_deref().unwrap_or("-")),
            Cell::new(obj.storage_class.as_deref().unwrap_or("-")),
        ]);
    }
    if objects.len() > 20 {
        println!("(showing first 20 of {})", objects.len());
    }
    println!("{t}");

    if !ctx.armed {
        println!(
            "\n{} {} object(s) would be downloaded to {}",
            "[DRY-RUN]".cyan().bold(),
            objects.len(),
            output_dir.display()
        );
        println!(
            "{}",
            "Run with --armed to perform the actual download.".yellow()
        );
        return Ok(());
    }

    // ── Armed: download objects ────────────────────────────────────────────
    println!(
        "\n{} Downloading {} object(s) to {}",
        "[ARMED]".red().bold(),
        objects.len(),
        output_dir.display()
    );

    tokio::fs::create_dir_all(&output_dir)
        .await
        .with_context(|| format!("failed to create output dir: {}", output_dir.display()))?;

    let total = objects.len();
    for (idx, obj) in objects.iter().enumerate() {
        // Determine local file path, preserving S3 key structure.
        let local_path = {
            let rel = obj.key.replace('/', std::path::MAIN_SEPARATOR_STR);
            output_dir.join(rel)
        };

        // Ensure parent directory exists
        if let Some(parent) = local_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| {
                    format!("failed to create directory: {}", parent.display())
                })?;
        }

        // GetObject
        let resp = s3
            .get_object()
            .bucket(bucket)
            .key(&obj.key)
            .send()
            .await
            .with_context(|| format!("s3:GetObject failed for key: {}", obj.key))?;

        let bytes = resp
            .body
            .collect()
            .await
            .with_context(|| format!("failed to read body for key: {}", obj.key))?
            .into_bytes();

        tokio::fs::write(&local_path, &bytes)
            .await
            .with_context(|| format!("failed to write file: {}", local_path.display()))?;

        println!(
            "  Downloaded {}/{}: {} ({} bytes)",
            idx + 1,
            total,
            obj.key.yellow(),
            bytes.len()
        );
    }

    println!(
        "\n{}",
        format!("Downloaded {total}/{total} objects to {}", output_dir.display()).green()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "s3__download_bucket",
            author: "lancer-pacu",
            category: "EXFIL",
            one_liner: "List (dry-run) or download (--armed) objects from an S3 bucket.",
            services: &["S3"],
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

    /// Module is registered in the inventory.
    #[test]
    fn module_registered_in_inventory() {
        let found = inventory::iter::<Module>
            .into_iter()
            .any(|m| m.info.name == "s3__download_bucket");
        assert!(found, "s3__download_bucket not found in inventory");
    }

    /// Category is EXFIL.
    #[test]
    fn module_category_is_exfil() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "s3__download_bucket")
            .expect("s3__download_bucket not found");
        assert_eq!(m.info.category, "EXFIL");
    }

    /// Missing --bucket returns an error.
    #[tokio::test]
    async fn missing_bucket_returns_error() {
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
        let result = super::run(&ctx, &[]).await;
        assert!(result.is_err(), "expected error when --bucket is missing");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("--bucket"), "error should mention --bucket: {msg}");
    }

    /// S3ObjectMeta serialises and deserialises correctly.
    #[test]
    fn s3_object_meta_serde_round_trip() {
        let meta = S3ObjectMeta {
            key: "logs/2024/01/01/app.log".to_owned(),
            size_bytes: 1048576,
            last_modified: Some("2024-01-01T00:00:00Z".to_owned()),
            storage_class: Some("STANDARD".to_owned()),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: S3ObjectMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, "logs/2024/01/01/app.log");
        assert_eq!(back.size_bytes, 1048576);
        assert_eq!(back.storage_class.as_deref(), Some("STANDARD"));
    }
}
