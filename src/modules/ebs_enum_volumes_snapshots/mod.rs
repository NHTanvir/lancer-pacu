//! ebs__enum_volumes_snapshots — focused EBS volume and snapshot enumeration.
//!
//! Args:
//!   --owner <owner_id>   filter snapshots by owner (default: "self")
//!   --public             also list publicly accessible snapshots
//!
//! Calls:
//!   - ec2:DescribeVolumes
//!   - ec2:DescribeSnapshots (with owner filter)

use anyhow::Context as _;
use colored::Colorize;
use comfy_table::{Cell, Table, presets::UTF8_FULL};
use serde::{Deserialize, Serialize};

use crate::module::{AwsContext, Module, ModuleInfo};

// Re-use structs from ec2_enum for consistency.
pub use crate::modules::ec2_enum::{Ec2Snapshot, Ec2Volume};

// ---------------------------------------------------------------------------
// Helper: format DateTime
// ---------------------------------------------------------------------------

fn fmt_dt(dt: &aws_sdk_ec2::primitives::DateTime) -> String {
    dt.fmt(aws_sdk_ec2::primitives::DateTimeFormat::DateTime)
        .unwrap_or_else(|_| "<invalid-date>".to_owned())
}

// ---------------------------------------------------------------------------
// Additional snapshot type for public results
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicSnapshot {
    pub snapshot_id: String,
    pub owner_id: Option<String>,
    pub volume_id: Option<String>,
    pub state: String,
    pub encrypted: bool,
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let owner: &str = {
        let pos = args.iter().position(|&a| a == "--owner");
        pos.and_then(|i| args.get(i + 1).copied()).unwrap_or("self")
    };
    let include_public = args.contains(&"--public");

    let ec2 = aws_sdk_ec2::Client::new(&ctx.sdk_config);

    // ── 1. DescribeVolumes ─────────────────────────────────────────────────
    println!("{}", "Enumerating EBS volumes…".cyan());
    let mut volumes: Vec<Ec2Volume> = Vec::new();
    {
        let mut paginator = ec2.describe_volumes().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let page = page.context("ec2:DescribeVolumes page failed")?;
            for vol in page.volumes() {
                volumes.push(Ec2Volume {
                    volume_id: vol.volume_id().unwrap_or("<unknown>").to_owned(),
                    size_gib: vol.size().unwrap_or(0),
                    state: vol
                        .state()
                        .map(|s| s.as_str().to_owned())
                        .unwrap_or_else(|| "<unknown>".to_owned()),
                    availability_zone: vol
                        .availability_zone()
                        .unwrap_or("<unknown>")
                        .to_owned(),
                    encrypted: vol.encrypted().unwrap_or(false),
                });
            }
        }
    }

    // ── 2. DescribeSnapshots with owner filter ─────────────────────────────
    println!(
        "{}",
        format!("Enumerating snapshots (owner={owner})…").cyan()
    );
    let mut snapshots: Vec<Ec2Snapshot> = Vec::new();
    {
        let mut paginator = ec2
            .describe_snapshots()
            .owner_ids(owner)
            .into_paginator()
            .send();
        while let Some(page) = paginator.next().await {
            let page = page.context("ec2:DescribeSnapshots page failed")?;
            for snap in page.snapshots() {
                snapshots.push(Ec2Snapshot {
                    snapshot_id: snap.snapshot_id().unwrap_or("<unknown>").to_owned(),
                    volume_id: snap.volume_id().map(|s| s.to_owned()),
                    state: snap
                        .state()
                        .map(|s| s.as_str().to_owned())
                        .unwrap_or_else(|| "<unknown>".to_owned()),
                    start_time: snap.start_time().map(fmt_dt),
                    encrypted: snap.encrypted().unwrap_or(false),
                });
            }
        }
    }

    // ── 3. (Optional) public snapshots ─────────────────────────────────────
    let mut public_snaps: Vec<PublicSnapshot> = Vec::new();
    if include_public {
        println!(
            "{}",
            "Enumerating public snapshots (RestorableBy=all)…".cyan()
        );
        let mut paginator = ec2
            .describe_snapshots()
            .restorable_by_user_ids("all")
            .into_paginator()
            .send();
        while let Some(page) = paginator.next().await {
            let page = page.context("ec2:DescribeSnapshots (public) page failed")?;
            for snap in page.snapshots() {
                public_snaps.push(PublicSnapshot {
                    snapshot_id: snap.snapshot_id().unwrap_or("<unknown>").to_owned(),
                    owner_id: snap.owner_id().map(|s| s.to_owned()),
                    volume_id: snap.volume_id().map(|s| s.to_owned()),
                    state: snap
                        .state()
                        .map(|s| s.as_str().to_owned())
                        .unwrap_or_else(|| "<unknown>".to_owned()),
                    encrypted: snap.encrypted().unwrap_or(false),
                    description: snap.description().map(|s| s.to_owned()),
                });
            }
        }
    }

    // ── Display volumes table ──────────────────────────────────────────────
    println!(
        "\n{} ({} found)",
        "─── EBS Volumes ─────────────────────────────────────────".cyan(),
        volumes.len()
    );
    if !volumes.is_empty() {
        let mut t = Table::new();
        t.load_preset(UTF8_FULL);
        t.set_header(vec!["Volume ID", "Size (GiB)", "State", "AZ", "Encrypted"]);
        for vol in volumes.iter().take(20) {
            t.add_row(vec![
                Cell::new(&vol.volume_id),
                Cell::new(vol.size_gib.to_string()),
                Cell::new(&vol.state),
                Cell::new(&vol.availability_zone),
                Cell::new(if vol.encrypted { "yes" } else { "no" }),
            ]);
        }
        if volumes.len() > 20 {
            println!("(showing first 20 of {})", volumes.len());
        }
        println!("{t}");
    }

    // ── Display snapshots table ────────────────────────────────────────────
    println!(
        "\n{} ({} found)",
        "─── EBS Snapshots ───────────────────────────────────────".cyan(),
        snapshots.len()
    );
    if !snapshots.is_empty() {
        let mut t = Table::new();
        t.load_preset(UTF8_FULL);
        t.set_header(vec!["Snapshot ID", "Volume ID", "State", "Start Time", "Encrypted"]);
        for snap in snapshots.iter().take(20) {
            t.add_row(vec![
                Cell::new(&snap.snapshot_id),
                Cell::new(snap.volume_id.as_deref().unwrap_or("-")),
                Cell::new(&snap.state),
                Cell::new(snap.start_time.as_deref().unwrap_or("-")),
                Cell::new(if snap.encrypted { "yes" } else { "no" }),
            ]);
        }
        if snapshots.len() > 20 {
            println!("(showing first 20 of {})", snapshots.len());
        }
        println!("{t}");
    }

    // ── Display public snapshots ───────────────────────────────────────────
    if include_public && !public_snaps.is_empty() {
        println!(
            "\n{} ({} found) {}",
            "─── Public Snapshots ────────────────────────────────────".cyan(),
            public_snaps.len(),
            "[POTENTIAL MISCONFIGURATION]".red().bold()
        );
        let mut t = Table::new();
        t.load_preset(UTF8_FULL);
        t.set_header(vec!["Snapshot ID", "Owner ID", "State", "Encrypted"]);
        for snap in public_snaps.iter().take(20) {
            t.add_row(vec![
                Cell::new(&snap.snapshot_id),
                Cell::new(snap.owner_id.as_deref().unwrap_or("-")),
                Cell::new(&snap.state),
                Cell::new(if snap.encrypted { "yes" } else { "no" }),
            ]);
        }
        if public_snaps.len() > 20 {
            println!("(showing first 20 of {})", public_snaps.len());
        }
        println!("{t}");
    }

    // ── Cache to session DB ────────────────────────────────────────────────
    if let Some(pool) = &ctx.db_pool {
        match crate::db::get_active_session(pool).await {
            Ok(Some(sess)) => {
                let vol_json = serde_json::to_string(&volumes)?;
                let snap_json = serde_json::to_string(&snapshots)?;
                if let Err(e) =
                    crate::db::update_session_data(pool, sess.id, "ec2_volumes", &vol_json).await
                {
                    eprintln!("{} ec2_volumes: {e}", "Warning: could not cache".yellow());
                }
                if let Err(e) =
                    crate::db::update_session_data(pool, sess.id, "ec2_snapshots", &snap_json)
                        .await
                {
                    eprintln!("{} ec2_snapshots: {e}", "Warning: could not cache".yellow());
                }
                println!("{}", "EBS data cached to session DB.".green());
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
            name: "ebs__enum_volumes_snapshots",
            author: "lancer-pacu",
            category: "ENUM",
            one_liner: "Enumerate EBS volumes and snapshots. Use --owner and --public for broader scope.",
            services: &["EC2"],
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
            .any(|m| m.info.name == "ebs__enum_volumes_snapshots");
        assert!(found, "ebs__enum_volumes_snapshots not found in inventory");
    }

    /// PublicSnapshot serialises and deserialises correctly.
    #[test]
    fn public_snapshot_serde_round_trip() {
        let snap = PublicSnapshot {
            snapshot_id: "snap-0abc123".to_owned(),
            owner_id: Some("123456789012".to_owned()),
            volume_id: Some("vol-0abc123".to_owned()),
            state: "completed".to_owned(),
            encrypted: false,
            description: Some("Test snapshot".to_owned()),
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: PublicSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.snapshot_id, "snap-0abc123");
        assert!(!back.encrypted);
        assert_eq!(back.state, "completed");
    }
}
