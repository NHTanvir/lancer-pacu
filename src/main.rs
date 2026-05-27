//! lancer-pacu — Rust clone of Pacu (Rhino Security Labs)
//! AUTHORIZED USE ONLY. Default --dry-run mode active.

mod commands;
mod module;
mod modules;
mod repl;

use clap::Parser;
use colored::Colorize;

use module::AwsContext;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "lancer-pacu",
    version,
    about = "Rust clone of Pacu — Lancer bug bounty toolkit"
)]
struct Cli {
    /// Enable state-mutating API calls (disabled by default for safety)
    #[arg(long)]
    armed: bool,

    /// Dry-run mode (default: true — log intent without executing writes)
    #[arg(long, default_value_t = true)]
    dry_run: bool,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // --armed overrides dry_run.
    let dry_run = if cli.armed { false } else { cli.dry_run };

    print_banner(cli.armed);

    let ctx = AwsContext::new(dry_run);
    repl::run(ctx).await
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

fn print_banner(armed: bool) {
    let top    = "╔══════════════════════════════════════════════════════════════╗";
    let line1  = "║  lancer-pacu — Rust clone of Pacu (Rhino Security Labs)     ║";
    let line2  = "║  AUTHORIZED USE ONLY. Default: --dry-run mode active.       ║";
    let line3  = "║  Use --armed flag to enable state-mutating API calls.       ║";
    let line4  = "║  This tool generates CloudTrail activity. Get authorization. ║";
    let bottom = "╚══════════════════════════════════════════════════════════════╝";

    if armed {
        println!("{}", top.red().bold());
        println!("{}", line1.red().bold());
        println!("{}", line2.yellow().bold());
        println!("{}", line3.yellow().bold());
        println!("{}", line4.red().bold());
        println!("{}", bottom.red().bold());
    } else {
        println!("{}", top.yellow());
        println!("{}", line1.yellow());
        println!("{}", line2.yellow());
        println!("{}", line3.yellow());
        println!("{}", line4.yellow());
        println!("{}", bottom.yellow());
    }
    println!();
}
