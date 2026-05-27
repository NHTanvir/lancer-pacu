//! REPL loop using rustyline.

use colored::Colorize;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

use crate::commands::{list, search, whoami};
use crate::module::{AwsContext, Module};

const HISTORY_FILE: &str = ".lancer-pacu-history";

const HELP_TEXT: &str = "\
Built-in commands:
  list                  — list all registered modules
  search <term>         — filter modules by name / category / service / one-liner
  whoami                — call STS GetCallerIdentity
  run <module> [args…]  — execute a registered module
  help                  — show this message
  exit / quit           — exit the REPL
";

/// Start the interactive REPL. Blocks until the user exits.
pub async fn run(ctx: AwsContext) -> anyhow::Result<()> {
    let mut rl = DefaultEditor::new()?;

    // Load history (ignore if it doesn't exist yet).
    let _ = rl.load_history(HISTORY_FILE);

    let mode_label = if ctx.armed {
        "ARMED".red().bold().to_string()
    } else {
        "dry-run".green().to_string()
    };
    println!("Mode: {mode_label}  |  type 'help' for commands.\n");

    loop {
        let readline = rl.readline("Pacu (lancer) > ");
        match readline {
            Ok(line) => {
                let line = line.trim().to_owned();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(&line);

                let parts: Vec<&str> = line.split(' ').collect();
                let cmd = parts[0];
                let args = &parts[1..];

                match cmd {
                    "exit" | "quit" => {
                        println!("Exiting lancer-pacu. Stay legal.");
                        break;
                    }
                    "help" => println!("{HELP_TEXT}"),
                    "list" => list::run(),
                    "search" => {
                        let term = args.join(" ");
                        search::run(&term);
                    }
                    "whoami" => whoami::run(&ctx).await,
                    "run" => {
                        if args.is_empty() {
                            println!("Usage: run <module_name> [args…]");
                            continue;
                        }
                        let module_name = args[0];
                        let module_args = &args[1..];

                        if ctx.dry_run {
                            println!("{}", "[DRY-RUN] Module will not execute state-mutating API calls. Use --armed to enable.".yellow());
                        }

                        let found: Option<&Module> = inventory::iter::<Module>
                            .into_iter()
                            .find(|m| m.info.name == module_name);

                        match found {
                            Some(module) => {
                                if let Err(e) = (module.run)(&ctx, module_args).await {
                                    eprintln!("{} {e}", "Module error:".red().bold());
                                }
                            }
                            None => {
                                eprintln!(
                                    "{} '{module_name}' not found. Try 'list' or 'search'.",
                                    "Unknown module:".red()
                                );
                            }
                        }
                    }
                    other => {
                        println!(
                            "{} '{}'. Type 'help' for commands.",
                            "Unknown command:".red(),
                            other
                        );
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("(Ctrl-C — type 'exit' to quit)");
            }
            Err(ReadlineError::Eof) => {
                println!("Exiting lancer-pacu. Stay legal.");
                break;
            }
            Err(e) => {
                eprintln!("REPL error: {e}");
                break;
            }
        }
    }

    let _ = rl.save_history(HISTORY_FILE);
    Ok(())
}
