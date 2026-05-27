//! vpc__enum_lateral_movement — enumerate VPC networking to map pivot paths.
//!
//! Category: LATERAL_MOVE. Services: ["EC2"].
//!
//! Read-only — always safe.
//!
//! Calls:
//!   - ec2:DescribeVpcs                       → VPCs (id, cidr, is_default, tags)
//!   - ec2:DescribeSubnets                    → subnets (id, vpc_id, cidr, az, available_ips)
//!   - ec2:DescribeRouteTables                → route tables (id, vpc_id, routes)
//!   - ec2:DescribeVpcPeeringConnections      → peering connections
//!   - ec2:DescribeTransitGatewayAttachments  → TGW attachments (best-effort)
//!
//! Results are cached to session DB under `extra` key as JSON.

use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Serialisable structs
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VpcInfo {
    pub vpc_id: String,
    pub cidr: String,
    pub is_default: bool,
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SubnetInfo {
    pub subnet_id: String,
    pub vpc_id: String,
    pub cidr: String,
    pub availability_zone: String,
    pub available_ips: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RouteEntry {
    pub destination: String,
    pub target: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RouteTableInfo {
    pub route_table_id: String,
    pub vpc_id: String,
    pub routes: Vec<RouteEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeeringConnectionInfo {
    pub id: String,
    pub requester_vpc: String,
    pub requester_account: String,
    pub accepter_vpc: String,
    pub accepter_account: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TgwAttachmentInfo {
    pub attachment_id: String,
    pub tgw_id: String,
    pub resource_type: String,
    pub resource_id: String,
    pub state: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VpcEnumResult {
    pub vpcs: Vec<VpcInfo>,
    pub subnets: Vec<SubnetInfo>,
    pub route_tables: Vec<RouteTableInfo>,
    pub peering_connections: Vec<PeeringConnectionInfo>,
    pub tgw_attachments: Vec<TgwAttachmentInfo>,
}

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, _args: &[&str]) -> anyhow::Result<()> {
    println!("{}", "vpc__enum_lateral_movement".cyan().bold());
    println!(
        "  {}",
        "Enumerates VPC networking resources to identify lateral movement pivot paths.\n".yellow()
    );

    let ec2 = aws_sdk_ec2::Client::new(&ctx.sdk_config);

    // ── Enumerate VPCs ─────────────────────────────────────────────────────
    println!("  {} Calling ec2:DescribeVpcs...", "[INFO]".cyan());
    let mut vpcs: Vec<VpcInfo> = Vec::new();
    match ec2.describe_vpcs().send().await {
        Ok(resp) => {
            for vpc in resp.vpcs() {
                let name = vpc
                    .tags()
                    .iter()
                    .find(|t| t.key().unwrap_or("") == "Name")
                    .and_then(|t| t.value())
                    .map(|s| s.to_owned());
                vpcs.push(VpcInfo {
                    vpc_id: vpc.vpc_id().unwrap_or("<unknown>").to_owned(),
                    cidr: vpc.cidr_block().unwrap_or("<unknown>").to_owned(),
                    is_default: vpc.is_default().unwrap_or(false),
                    name,
                });
            }
        }
        Err(e) => {
            eprintln!("  {} ec2:DescribeVpcs failed: {}", "[ERR]".red().bold(), e);
        }
    }

    println!(
        "  {} Found {} VPC(s):",
        "[FOUND]".green().bold(),
        vpcs.len()
    );
    for vpc in &vpcs {
        let default_label = if vpc.is_default { " (default)" } else { "" };
        println!(
            "    {} {} {}{}",
            vpc.vpc_id.yellow(),
            vpc.cidr.cyan(),
            vpc.name.as_deref().unwrap_or(""),
            default_label.dimmed()
        );
    }

    // ── Enumerate Subnets ──────────────────────────────────────────────────
    println!("\n  {} Calling ec2:DescribeSubnets...", "[INFO]".cyan());
    let mut subnets: Vec<SubnetInfo> = Vec::new();
    match ec2.describe_subnets().send().await {
        Ok(resp) => {
            for sn in resp.subnets() {
                subnets.push(SubnetInfo {
                    subnet_id: sn.subnet_id().unwrap_or("<unknown>").to_owned(),
                    vpc_id: sn.vpc_id().unwrap_or("<unknown>").to_owned(),
                    cidr: sn.cidr_block().unwrap_or("<unknown>").to_owned(),
                    availability_zone: sn.availability_zone().unwrap_or("<unknown>").to_owned(),
                    available_ips: sn.available_ip_address_count().unwrap_or(0),
                });
            }
        }
        Err(e) => {
            eprintln!("  {} ec2:DescribeSubnets failed: {}", "[ERR]".red().bold(), e);
        }
    }

    println!(
        "  {} Found {} subnet(s):",
        "[FOUND]".green().bold(),
        subnets.len()
    );
    for sn in &subnets {
        println!(
            "    {} vpc={} cidr={} az={} avail_ips={}",
            sn.subnet_id.yellow(),
            sn.vpc_id.cyan(),
            sn.cidr,
            sn.availability_zone,
            sn.available_ips
        );
    }

    // ── Unusual CIDR detection ─────────────────────────────────────────────
    let unusual: Vec<&SubnetInfo> = subnets
        .iter()
        .filter(|s| {
            // Flag subnets outside RFC-1918 ranges or very large ranges
            let cidr = &s.cidr;
            !cidr.starts_with("10.")
                && !cidr.starts_with("172.16.")
                && !cidr.starts_with("172.17.")
                && !cidr.starts_with("172.18.")
                && !cidr.starts_with("172.19.")
                && !cidr.starts_with("172.2")
                && !cidr.starts_with("172.3")
                && !cidr.starts_with("192.168.")
        })
        .collect();
    if !unusual.is_empty() {
        println!(
            "\n  {} {} subnet(s) with unusual (non-RFC-1918) CIDR ranges:",
            "[ALERT]".red().bold(),
            unusual.len()
        );
        for sn in &unusual {
            println!("    {} {}", sn.subnet_id.red(), sn.cidr.red());
        }
    }

    // ── Enumerate Route Tables ─────────────────────────────────────────────
    println!("\n  {} Calling ec2:DescribeRouteTables...", "[INFO]".cyan());
    let mut route_tables: Vec<RouteTableInfo> = Vec::new();
    match ec2.describe_route_tables().send().await {
        Ok(resp) => {
            for rt in resp.route_tables() {
                let mut routes: Vec<RouteEntry> = Vec::new();
                for route in rt.routes() {
                    let dest = route
                        .destination_cidr_block()
                        .or(route.destination_ipv6_cidr_block())
                        .or(route.destination_prefix_list_id())
                        .unwrap_or("<unknown>")
                        .to_owned();
                    let target = route
                        .gateway_id()
                        .or(route.transit_gateway_id())
                        .or(route.vpc_peering_connection_id())
                        .or(route.nat_gateway_id())
                        .or(route.instance_id())
                        .or(route.network_interface_id())
                        .unwrap_or("<local>")
                        .to_owned();
                    routes.push(RouteEntry { destination: dest, target });
                }
                route_tables.push(RouteTableInfo {
                    route_table_id: rt.route_table_id().unwrap_or("<unknown>").to_owned(),
                    vpc_id: rt.vpc_id().unwrap_or("<unknown>").to_owned(),
                    routes,
                });
            }
        }
        Err(e) => {
            eprintln!(
                "  {} ec2:DescribeRouteTables failed: {}",
                "[ERR]".red().bold(),
                e
            );
        }
    }

    println!(
        "  {} Found {} route table(s):",
        "[FOUND]".green().bold(),
        route_tables.len()
    );
    // Highlight route tables with cross-VPC routes
    let mut pivot_routes: Vec<(&RouteTableInfo, &RouteEntry)> = Vec::new();
    for rt in &route_tables {
        for route in &rt.routes {
            if route.target.starts_with("pcx-") || route.target.starts_with("tgw-") {
                pivot_routes.push((rt, route));
            }
        }
        println!(
            "    {} vpc={} routes={}",
            rt.route_table_id.yellow(),
            rt.vpc_id.cyan(),
            rt.routes.len()
        );
    }

    if !pivot_routes.is_empty() {
        println!(
            "\n  {} {} pivot route(s) found (peering or TGW targets):",
            "[ALERT]".red().bold(),
            pivot_routes.len()
        );
        for (rt, route) in &pivot_routes {
            println!(
                "    {} {} → {}",
                rt.route_table_id.yellow(),
                route.destination.cyan(),
                route.target.red()
            );
        }
    }

    // ── Enumerate VPC Peering Connections ──────────────────────────────────
    println!(
        "\n  {} Calling ec2:DescribeVpcPeeringConnections...",
        "[INFO]".cyan()
    );
    let mut peering_connections: Vec<PeeringConnectionInfo> = Vec::new();
    match ec2.describe_vpc_peering_connections().send().await {
        Ok(resp) => {
            for pc in resp.vpc_peering_connections() {
                let req = pc.requester_vpc_info();
                let acc = pc.accepter_vpc_info();
                peering_connections.push(PeeringConnectionInfo {
                    id: pc.vpc_peering_connection_id().unwrap_or("<unknown>").to_owned(),
                    requester_vpc: req
                        .and_then(|r| r.vpc_id())
                        .unwrap_or("<unknown>")
                        .to_owned(),
                    requester_account: req
                        .and_then(|r| r.owner_id())
                        .unwrap_or("<unknown>")
                        .to_owned(),
                    accepter_vpc: acc
                        .and_then(|a| a.vpc_id())
                        .unwrap_or("<unknown>")
                        .to_owned(),
                    accepter_account: acc
                        .and_then(|a| a.owner_id())
                        .unwrap_or("<unknown>")
                        .to_owned(),
                    status: pc
                        .status()
                        .and_then(|s| s.code())
                        .map(|c| format!("{:?}", c))
                        .unwrap_or("<unknown>".to_owned()),
                });
            }
        }
        Err(e) => {
            eprintln!(
                "  {} ec2:DescribeVpcPeeringConnections failed: {}",
                "[ERR]".red().bold(),
                e
            );
        }
    }

    if peering_connections.is_empty() {
        println!("  {} No VPC peering connections found.", "[INFO]".cyan());
    } else {
        println!(
            "  {} {} VPC peering connection(s) — potential pivot paths:",
            "[ALERT]".red().bold(),
            peering_connections.len()
        );
        for pc in &peering_connections {
            println!(
                "    {} {} (acct:{}) <-> {} (acct:{}) status={}",
                pc.id.yellow(),
                pc.requester_vpc.cyan(),
                pc.requester_account,
                pc.accepter_vpc.cyan(),
                pc.accepter_account,
                pc.status
            );
        }
    }

    // ── Enumerate Transit Gateway Attachments (best-effort) ────────────────
    println!(
        "\n  {} Calling ec2:DescribeTransitGatewayAttachments (best-effort)...",
        "[INFO]".cyan()
    );
    let mut tgw_attachments: Vec<TgwAttachmentInfo> = Vec::new();
    match ec2.describe_transit_gateway_attachments().send().await {
        Ok(resp) => {
            for att in resp.transit_gateway_attachments() {
                tgw_attachments.push(TgwAttachmentInfo {
                    attachment_id: att
                        .transit_gateway_attachment_id()
                        .unwrap_or("<unknown>")
                        .to_owned(),
                    tgw_id: att.transit_gateway_id().unwrap_or("<unknown>").to_owned(),
                    resource_type: att
                        .resource_type()
                        .map(|t| format!("{:?}", t))
                        .unwrap_or("<unknown>".to_owned()),
                    resource_id: att.resource_id().unwrap_or("<unknown>").to_owned(),
                    state: att
                        .state()
                        .map(|s| format!("{:?}", s))
                        .unwrap_or("<unknown>".to_owned()),
                });
            }
            println!(
                "  {} Found {} TGW attachment(s):",
                "[FOUND]".green().bold(),
                tgw_attachments.len()
            );
            for att in &tgw_attachments {
                println!(
                    "    {} tgw={} type={} resource={} state={}",
                    att.attachment_id.yellow(),
                    att.tgw_id.cyan(),
                    att.resource_type,
                    att.resource_id,
                    att.state
                );
            }
        }
        Err(e) => {
            println!(
                "  {} ec2:DescribeTransitGatewayAttachments — insufficient permissions or no TGWs: {}",
                "[WARN]".yellow(),
                e
            );
        }
    }

    // ── Summary ────────────────────────────────────────────────────────────
    println!("\n  {} VPC Lateral Movement Summary:", "[SUMMARY]".blue().bold());
    println!("    VPCs:                   {}", vpcs.len());
    println!("    Subnets:                {}", subnets.len());
    println!("    Route Tables:           {}", route_tables.len());
    println!("    VPC Peering (pivots):   {}", peering_connections.len());
    println!("    TGW Attachments:        {}", tgw_attachments.len());
    println!("    Routes to other VPCs:   {}", pivot_routes.len());

    // ── Cache to session DB ────────────────────────────────────────────────
    let result = VpcEnumResult {
        vpcs,
        subnets,
        route_tables,
        peering_connections,
        tgw_attachments,
    };

    if let Some(pool) = &ctx.db_pool {
        let extra = serde_json::to_string(&result).unwrap_or_default();
        let _ = sqlx::query(
            "INSERT INTO sessions (module, extra) VALUES (?, ?)",
        )
        .bind("vpc__enum_lateral_movement")
        .bind(extra)
        .execute(pool)
        .await;
        println!("\n  {} Results cached to session DB.", "[DB]".green());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "vpc__enum_lateral_movement",
            author: "lancer-pacu",
            category: "LATERAL_MOVE",
            one_liner: "Enumerate VPC networking (VPCs, subnets, routes, peering, TGWs) to map pivot paths.",
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
    use crate::module::Module;

    #[test]
    fn module_registered_in_inventory() {
        let found = inventory::iter::<Module>
            .into_iter()
            .any(|m| m.info.name == "vpc__enum_lateral_movement");
        assert!(found, "vpc__enum_lateral_movement not found in inventory");
    }

    #[test]
    fn module_category_is_lateral_move() {
        let m = inventory::iter::<Module>
            .into_iter()
            .find(|m| m.info.name == "vpc__enum_lateral_movement")
            .expect("vpc__enum_lateral_movement not found");
        assert_eq!(m.info.category, "LATERAL_MOVE");
    }

    #[test]
    fn vpc_info_struct_serializes() {
        let vpc = super::VpcInfo {
            vpc_id: "vpc-12345".to_string(),
            cidr: "10.0.0.0/16".to_string(),
            is_default: false,
            name: Some("production".to_string()),
        };
        let json = serde_json::to_string(&vpc).expect("serialization failed");
        assert!(json.contains("vpc-12345"));
        assert!(json.contains("10.0.0.0/16"));
        assert!(json.contains("production"));
    }

    #[test]
    fn subnet_info_struct_serializes() {
        let sn = super::SubnetInfo {
            subnet_id: "subnet-abc123".to_string(),
            vpc_id: "vpc-12345".to_string(),
            cidr: "10.0.1.0/24".to_string(),
            availability_zone: "us-east-1a".to_string(),
            available_ips: 250,
        };
        let json = serde_json::to_string(&sn).expect("serialization failed");
        assert!(json.contains("subnet-abc123"));
        assert!(json.contains("10.0.1.0/24"));
        assert!(json.contains("us-east-1a"));
    }

    #[test]
    fn peering_connection_struct_serializes() {
        let pc = super::PeeringConnectionInfo {
            id: "pcx-00112233".to_string(),
            requester_vpc: "vpc-aaa".to_string(),
            requester_account: "111111111111".to_string(),
            accepter_vpc: "vpc-bbb".to_string(),
            accepter_account: "222222222222".to_string(),
            status: "Active".to_string(),
        };
        let json = serde_json::to_string(&pc).expect("serialization failed");
        assert!(json.contains("pcx-00112233"));
        assert!(json.contains("vpc-aaa"));
        assert!(json.contains("vpc-bbb"));
    }

    #[test]
    fn vpc_enum_result_roundtrip() {
        let result = super::VpcEnumResult {
            vpcs: vec![super::VpcInfo {
                vpc_id: "vpc-test".to_string(),
                cidr: "172.16.0.0/12".to_string(),
                is_default: true,
                name: None,
            }],
            subnets: vec![],
            route_tables: vec![],
            peering_connections: vec![],
            tgw_attachments: vec![],
        };
        let json = serde_json::to_string(&result).expect("serialize failed");
        let decoded: super::VpcEnumResult =
            serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(decoded.vpcs.len(), 1);
        assert_eq!(decoded.vpcs[0].vpc_id, "vpc-test");
    }

    #[tokio::test]
    async fn run_with_no_creds_does_not_panic() {
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
        // Should not panic; AWS calls will fail gracefully
        let _ = super::run(&ctx, &[]).await;
    }
}
