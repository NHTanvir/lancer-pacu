//! lancer-pacu
//! Rust clone of pacu. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-pacu", version, about = "Rust clone of pacu")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-pacu - scaffold ready. Implement per plan.md.");
    Ok(())
}
