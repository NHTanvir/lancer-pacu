//! ec2__enum — enumerate EC2 resources for the current account/region.
//!
//! Calls (paginated):
//!   - ec2:DescribeInstances        → instances
//!   - ec2:DescribeSecurityGroups   → security groups
//!   - ec2:DescribeImages           → AMIs (owner=self)
//!   - ec2:DescribeVolumes          → EBS volumes
//!   - ec2:DescribeSnapshots        → snapshots (owner=self)
//!
//! Results are cached to the session DB and a summary is printed.

use anyhow::Context as _;
use colored::Colorize;
use comfy_table::{Cell, Table, presets::UTF8_FULL};
use serde::{Deserialize, Serialize};

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Serialisable structs
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ec2Instance {
    pub instance_id: String,
    pub instance_type: String,
    pub state: String,
    pub public_ip: Option<String>,
    pub private_ip: Option<String>,
    pub image_id: String,
    pub key_name: Option<String>,
    pub launch_time: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ec2SecurityGroup {
    pub group_id: String,
    pub group_name: String,
    pub description: String,
    pub vpc_id: Option<String>,
    pub inbound_rule_count: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ec2Ami {
    pub image_id: String,
    pub name: Option<String>,
    pub state: String,
    pub creation_date: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ec2Volume {
    pub volume_id: String,
    pub size_gib: i32,
    pub state: String,
    pub availability_zone: String,
    pub encrypted: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ec2Snapshot {
    pub snapshot_id: String,
    pub volume_id: Option<String>,
    pub state: String,
    pub start_time: Option<String>,
    pub encrypted: bool,
}

// ---------------------------------------------------------------------------
// Helper: format DateTime
// ---------------------------------------------------------------------------

fn fmt_dt(dt: &aws_sdk_ec2::primitives::DateTime) -> String {
    dt.fmt(aws_sdk_ec2::primitives::DateTimeFormat::DateTime)
        .unwrap_or_else(|_| "<invalid-date>".to_owned())
}

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, _args: &[&str]) -> anyhow::Result<()> {
    let ec2 = aws_sdk_ec2::Client::new(&ctx.sdk_config);

    // ── 1. DescribeInstances ───────────────────────────────────────────────
    println!("{}", "Enumerating EC2 instances…".cyan());
    let mut instances: Vec<Ec2Instance> = Vec::new();
    {
        let mut paginator = ec2.describe_instances().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let page = page.context("ec2:DescribeInstances page failed")?;
            for reservation in page.reservations() {
                for inst in reservation.instances() {
                    instances.push(Ec2Instance {
                        instance_id: inst
                            .instance_id()
                            .unwrap_or("<unknown>")
                            .to_owned(),
                        instance_type: inst
                            .instance_type()
                            .map(|t| t.as_str().to_owned())
                            .unwrap_or_else(|| "<unknown>".to_owned()),
                        state: inst
                            .state()
                            .and_then(|s| s.name())
                            .map(|n| n.as_str().to_owned())
                            .unwrap_or_else(|| "<unknown>".to_owned()),
                        public_ip: inst.public_ip_address().map(|s| s.to_owned()),
                        private_ip: inst.private_ip_address().map(|s| s.to_owned()),
                        image_id: inst.image_id().unwrap_or("<unknown>").to_owned(),
                        key_name: inst.key_name().map(|s| s.to_owned()),
                        launch_time: inst.launch_time().map(fmt_dt),
                    });
                }
            }
        }
    }

    // ── 2. DescribeSecurityGroups ──────────────────────────────────────────
    println!("{}", "Enumerating security groups…".cyan());
    let mut security_groups: Vec<Ec2SecurityGroup> = Vec::new();
    {
        let mut paginator = ec2.describe_security_groups().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let page = page.context("ec2:DescribeSecurityGroups page failed")?;
            for sg in page.security_groups() {
                security_groups.push(Ec2SecurityGroup {
                    group_id: sg.group_id().unwrap_or("<unknown>").to_owned(),
                    group_name: sg.group_name().unwrap_or("<unknown>").to_owned(),
                    description: sg.description().unwrap_or("").to_owned(),
                    vpc_id: sg.vpc_id().map(|s| s.to_owned()),
                    inbound_rule_count: sg.ip_permissions().len(),
                });
            }
        }
    }

    // ── 3. DescribeImages (owner = self) ───────────────────────────────────
    println!("{}", "Enumerating AMIs (owner=self)…".cyan());
    let mut amis: Vec<Ec2Ami> = Vec::new();
    {
        let mut paginator = ec2
            .describe_images()
            .owners("self")
            .into_paginator()
            .send();
        while let Some(page) = paginator.next().await {
            let page = page.context("ec2:DescribeImages page failed")?;
            for img in page.images() {
                amis.push(Ec2Ami {
                    image_id: img.image_id().unwrap_or("<unknown>").to_owned(),
                    name: img.name().map(|s| s.to_owned()),
                    state: img
                        .state()
                        .map(|s| s.as_str().to_owned())
                        .unwrap_or_else(|| "<unknown>".to_owned()),
                    creation_date: img.creation_date().map(|s| s.to_owned()),
                });
            }
        }
    }

    // ── 4. DescribeVolumes ─────────────────────────────────────────────────
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

    // ── 5. DescribeSnapshots (owner = self) ────────────────────────────────
    println!("{}", "Enumerating snapshots (owner=self)…".cyan());
    let mut snapshots: Vec<Ec2Snapshot> = Vec::new();
    {
        let mut paginator = ec2
            .describe_snapshots()
            .owner_ids("self")
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

    // ── Display summary ────────────────────────────────────────────────────
    println!(
        "\n{}",
        "─── EC2 Enumeration Summary ─────────────────────────────".cyan()
    );
    println!(
        "  Enumerated {} instances, {} security groups, {} AMIs, {} volumes, {} snapshots",
        instances.len().to_string().green().bold(),
        security_groups.len().to_string().green().bold(),
        amis.len().to_string().green().bold(),
        volumes.len().to_string().green().bold(),
        snapshots.len().to_string().green().bold(),
    );

    // Print instance table (first 10)
    if !instances.is_empty() {
        let mut t = Table::new();
        t.load_preset(UTF8_FULL);
        t.set_header(vec!["Instance ID", "Type", "State", "Public IP", "Private IP"]);
        for inst in instances.iter().take(10) {
            t.add_row(vec![
                Cell::new(&inst.instance_id),
                Cell::new(&inst.instance_type),
                Cell::new(&inst.state),
                Cell::new(inst.public_ip.as_deref().unwrap_or("-")),
                Cell::new(inst.private_ip.as_deref().unwrap_or("-")),
            ]);
        }
        if instances.len() > 10 {
            println!("(showing first 10 of {})", instances.len());
        }
        println!("{t}");
    }

    // ── Cache to session DB ────────────────────────────────────────────────
    if let Some(pool) = &ctx.db_pool {
        match crate::db::get_active_session(pool).await {
            Ok(Some(sess)) => {
                macro_rules! cache_col {
                    ($col:expr, $data:expr) => {
                        match serde_json::to_string($data) {
                            Ok(json) => {
                                if let Err(e) = crate::db::update_session_data(
                                    pool, sess.id, $col, &json,
                                )
                                .await
                                {
                                    eprintln!(
                                        "{} {}: {e}",
                                        "Warning: could not cache".yellow(),
                                        $col
                                    );
                                }
                            }
                            Err(e) => eprintln!(
                                "{} {}: {e}",
                                "Warning: serialisation failed for".yellow(),
                                $col
                            ),
                        }
                    };
                }

                cache_col!("ec2_instances", &instances);
                cache_col!("ec2_security_groups", &security_groups);
                cache_col!("ec2_amis", &amis);
                cache_col!("ec2_volumes", &volumes);
                cache_col!("ec2_snapshots", &snapshots);

                println!("{}", "EC2 data cached to session DB.".green());
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
            name: "ec2__enum",
            author: "lancer-pacu",
            category: "ENUM",
            one_liner: "Enumerate EC2 instances, security groups, AMIs, volumes, and snapshots.",
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
            .any(|m| m.info.name == "ec2__enum");
        assert!(found, "ec2__enum not found in inventory");
    }

    /// EC2 instance struct serialises and deserialises correctly.
    #[test]
    fn ec2_instance_serde_round_trip() {
        let inst = Ec2Instance {
            instance_id: "i-0abcdef1234567890".to_owned(),
            instance_type: "t3.micro".to_owned(),
            state: "running".to_owned(),
            public_ip: Some("1.2.3.4".to_owned()),
            private_ip: Some("10.0.0.5".to_owned()),
            image_id: "ami-0123456789abcdef0".to_owned(),
            key_name: Some("my-key".to_owned()),
            launch_time: Some("2024-01-01T00:00:00Z".to_owned()),
        };
        let json = serde_json::to_string(&inst).unwrap();
        let back: Ec2Instance = serde_json::from_str(&json).unwrap();
        assert_eq!(back.instance_id, "i-0abcdef1234567890");
        assert_eq!(back.instance_type, "t3.micro");
        assert_eq!(back.state, "running");
        assert_eq!(back.public_ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(back.private_ip.as_deref(), Some("10.0.0.5"));
    }

    /// EC2 security group serialises and deserialises correctly.
    #[test]
    fn ec2_security_group_serde_round_trip() {
        let sg = Ec2SecurityGroup {
            group_id: "sg-0abc123".to_owned(),
            group_name: "my-sg".to_owned(),
            description: "Test SG".to_owned(),
            vpc_id: Some("vpc-0abc123".to_owned()),
            inbound_rule_count: 3,
        };
        let json = serde_json::to_string(&sg).unwrap();
        let back: Ec2SecurityGroup = serde_json::from_str(&json).unwrap();
        assert_eq!(back.group_id, "sg-0abc123");
        assert_eq!(back.inbound_rule_count, 3);
    }
}
