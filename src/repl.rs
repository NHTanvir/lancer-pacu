//! REPL loop using rustyline.

use colored::Colorize;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

use crate::commands::{list, proxy, search, sessions, whoami};
use crate::module::{AwsContext, Module};

const HISTORY_FILE: &str = ".lancer-pacu-history";

const HELP_TEXT: &str = "\
Built-in commands:
  list                              — list all registered modules
  search <term>                     — filter modules by name / category / service / one-liner
  whoami                            — call STS GetCallerIdentity
  run <module> [args…]              — execute a registered module
  help                              — show this message
  exit / quit                       — exit the REPL

Session commands:
  new_session <name>                — create a new session and set it active
  load_session <name>               — load an existing session and set it active
  list_sessions                     — list all sessions (ID | Name | Created | Active | Keys)
  set_keys <ak> <sk> [token]        — store AWS keys in the active session
  set_keys_imds                     — fetch credentials from IMDSv2 and store in active session
  swap_keys <session_name>          — load another session's keys and verify via STS
  data [resource_type]              — show cached JSON data from the active session
  services                          — show which resource types have cached data
  export [filename]                 — export the active session to a JSON file
  import <filename>                 — import a session from a JSON file and set it active

Proxy commands:
  set_proxy <socks5://host:port>    — configure a SOCKS5 proxy for the active session
  proxy                             — show the currently configured proxy
  clear_proxy                       — remove the proxy setting from the active session
";

/// Start the interactive REPL. Blocks until the user exits.
pub async fn run(mut ctx: AwsContext) -> anyhow::Result<()> {
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

                    // -------------------------------------------------------
                    // Session commands
                    // -------------------------------------------------------
                    "list_sessions" => {
                        if let Some(pool) = &ctx.db_pool {
                            sessions::cmd_list_sessions(pool).await;
                        } else {
                            eprintln!("{}", "Session DB unavailable.".red());
                        }
                    }
                    "new_session" => {
                        let name = args.first().copied().unwrap_or("");
                        if let Some(pool) = ctx.db_pool.clone() {
                            if let Some(new_ctx) =
                                sessions::cmd_new_session(&pool, name, ctx.dry_run).await
                            {
                                ctx = AwsContext { db_pool: Some(pool), ..new_ctx };
                            }
                        } else {
                            eprintln!("{}", "Session DB unavailable.".red());
                        }
                    }
                    "load_session" => {
                        let name = args.first().copied().unwrap_or("");
                        if let Some(pool) = ctx.db_pool.clone() {
                            if let Some(new_ctx) =
                                sessions::cmd_load_session(&pool, name, ctx.dry_run).await
                            {
                                ctx = AwsContext { db_pool: Some(pool), ..new_ctx };
                            }
                        } else {
                            eprintln!("{}", "Session DB unavailable.".red());
                        }
                    }
                    "set_keys" => {
                        if let Some(pool) = ctx.db_pool.clone() {
                            if let Some(new_ctx) =
                                sessions::cmd_set_keys(&pool, args, ctx.dry_run).await
                            {
                                ctx = AwsContext { db_pool: Some(pool), ..new_ctx };
                            }
                        } else {
                            eprintln!("{}", "Session DB unavailable.".red());
                        }
                    }
                    "swap_keys" => {
                        let session_name = args.first().copied().unwrap_or("");
                        if let Some(pool) = ctx.db_pool.clone() {
                            if let Some(new_ctx) =
                                sessions::cmd_swap_keys(&pool, session_name, ctx.dry_run).await
                            {
                                ctx = AwsContext { db_pool: Some(pool), ..new_ctx };
                            }
                        } else {
                            eprintln!("{}", "Session DB unavailable.".red());
                        }
                    }
                    "data" => {
                        let resource_type = args.first().copied();
                        if let Some(pool) = &ctx.db_pool {
                            sessions::cmd_data(pool, resource_type).await;
                        } else {
                            eprintln!("{}", "Session DB unavailable.".red());
                        }
                    }
                    "services" => {
                        if let Some(pool) = &ctx.db_pool {
                            sessions::cmd_services(pool).await;
                        } else {
                            eprintln!("{}", "Session DB unavailable.".red());
                        }
                    }

                    // -------------------------------------------------------
                    // Export / Import
                    // -------------------------------------------------------
                    "export" => {
                        if let Some(pool) = &ctx.db_pool {
                            sessions::cmd_export(pool, args).await;
                        } else {
                            eprintln!("{}", "Session DB unavailable.".red());
                        }
                    }
                    "import" => {
                        if let Some(pool) = ctx.db_pool.clone() {
                            if let Some(new_ctx) =
                                sessions::cmd_import(&pool, args, ctx.dry_run).await
                            {
                                ctx = AwsContext { db_pool: Some(pool), ..new_ctx };
                            }
                        } else {
                            eprintln!("{}", "Session DB unavailable.".red());
                        }
                    }

                    // -------------------------------------------------------
                    // IMDSv2
                    // -------------------------------------------------------
                    "set_keys_imds" => {
                        if let Some(pool) = ctx.db_pool.clone() {
                            if let Some(new_ctx) =
                                sessions::cmd_set_keys_imds(&pool, ctx.dry_run).await
                            {
                                ctx = AwsContext { db_pool: Some(pool), ..new_ctx };
                            }
                        } else {
                            eprintln!("{}", "Session DB unavailable.".red());
                        }
                    }

                    // -------------------------------------------------------
                    // Proxy
                    // -------------------------------------------------------
                    "set_proxy" => {
                        if let Some(pool) = &ctx.db_pool {
                            proxy::cmd_set_proxy(pool, args).await;
                        } else {
                            eprintln!("{}", "Session DB unavailable.".red());
                        }
                    }
                    "proxy" => {
                        if let Some(pool) = &ctx.db_pool {
                            proxy::cmd_show_proxy(pool).await;
                        } else {
                            eprintln!("{}", "Session DB unavailable.".red());
                        }
                    }
                    "clear_proxy" => {
                        if let Some(pool) = &ctx.db_pool {
                            proxy::cmd_clear_proxy(pool).await;
                        } else {
                            eprintln!("{}", "Session DB unavailable.".red());
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
