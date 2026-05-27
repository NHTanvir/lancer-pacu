//! Session-management REPL commands:
//!   new_session, load_session, list_sessions, set_keys, swap_keys, data, services

use colored::Colorize;
use comfy_table::{presets::UTF8_FULL, Cell, Table};
use sqlx::SqlitePool;

use crate::db;
use crate::module::AwsContext;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// All enumerable resource field names in the Session struct.
const ALL_DATA_FIELDS: &[&str] = &[
    "iam_users", "iam_roles", "iam_groups", "iam_policies", "iam_permissions",
    "ec2_instances", "ec2_security_groups", "ec2_amis", "ec2_volumes", "ec2_snapshots",
    "s3_buckets", "lambda_functions", "extra",
];

// ---------------------------------------------------------------------------
// list_sessions
// ---------------------------------------------------------------------------

/// Print all sessions as a comfy-table.
pub async fn cmd_list_sessions(pool: &SqlitePool) {
    match db::list_sessions(pool).await {
        Err(e) => eprintln!("{} {e}", "list_sessions error:".red().bold()),
        Ok(sessions) => {
            if sessions.is_empty() {
                println!("No sessions found. Use 'new_session <name>' to create one.");
                return;
            }

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["ID", "Name", "Created", "Active", "Keys"]);

            for s in &sessions {
                let active_str = if s.is_active() {
                    "* active".green().bold().to_string()
                } else {
                    String::new()
                };
                let keys_str = if s.access_key_id.is_some() {
                    format!(
                        "{}…",
                        &s.access_key_id.as_deref().unwrap_or("")[..4.min(
                            s.access_key_id.as_deref().unwrap_or("").len()
                        )]
                    )
                } else {
                    "(none)".to_string()
                };
                table.add_row(vec![
                    Cell::new(s.id.to_string()),
                    Cell::new(&s.name),
                    Cell::new(&s.created_at),
                    Cell::new(active_str),
                    Cell::new(keys_str),
                ]);
            }
            println!("{table}");
        }
    }
}

// ---------------------------------------------------------------------------
// new_session
// ---------------------------------------------------------------------------

/// Create a new session and set it as active. Returns the new AwsContext if
/// the session had stored credentials (unlikely for a brand-new session).
pub async fn cmd_new_session(pool: &SqlitePool, name: &str, dry_run: bool) -> Option<AwsContext> {
    if name.is_empty() {
        println!("Usage: new_session <name>");
        return None;
    }
    match db::new_session(pool, name).await {
        Err(e) => {
            eprintln!("{} {e}", "new_session error:".red().bold());
            None
        }
        Ok(sess) => {
            if let Err(e) = db::set_active_session(pool, name).await {
                eprintln!("{} {e}", "set_active_session error:".red().bold());
            }
            println!(
                "{} '{}' (id={}).",
                "Created and activated session:".green().bold(),
                sess.name,
                sess.id
            );
            build_ctx_from_session(&sess, dry_run).await
        }
    }
}

// ---------------------------------------------------------------------------
// load_session
// ---------------------------------------------------------------------------

/// Load an existing session and set it as active. Returns updated AwsContext.
pub async fn cmd_load_session(
    pool: &SqlitePool,
    name: &str,
    dry_run: bool,
) -> Option<AwsContext> {
    if name.is_empty() {
        println!("Usage: load_session <name>");
        return None;
    }
    match db::load_session(pool, name).await {
        Err(e) => {
            eprintln!("{} {e}", "load_session error:".red().bold());
            None
        }
        Ok(sess) => {
            if let Err(e) = db::set_active_session(pool, name).await {
                eprintln!("{} {e}", "set_active_session error:".red().bold());
            }
            println!(
                "{} '{}' (id={}).",
                "Loaded and activated session:".green().bold(),
                sess.name,
                sess.id
            );
            build_ctx_from_session(&sess, dry_run).await
        }
    }
}

// ---------------------------------------------------------------------------
// set_keys
// ---------------------------------------------------------------------------

/// Store AWS keys in the active session and rebuild AwsContext.
/// Usage: set_keys <access_key> <secret_key> [session_token]
pub async fn cmd_set_keys(
    pool: &SqlitePool,
    args: &[&str],
    dry_run: bool,
) -> Option<AwsContext> {
    if args.len() < 2 {
        println!("Usage: set_keys <access_key> <secret_key> [session_token]");
        return None;
    }
    let ak = args[0];
    let sk = args[1];
    let token = args.get(2).copied();

    let active = match db::get_active_session(pool).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            eprintln!(
                "{}",
                "No active session. Use 'new_session' or 'load_session' first.".red()
            );
            return None;
        }
        Err(e) => {
            eprintln!("{} {e}", "get_active_session error:".red().bold());
            return None;
        }
    };

    if let Err(e) =
        db::update_session_keys(pool, active.id, ak, sk, token, None, active.region.as_deref())
            .await
    {
        eprintln!("{} {e}", "update_session_keys error:".red().bold());
        return None;
    }

    println!("{}", "Keys stored in active session.".green().bold());
    let updated = db::load_session(pool, &active.name).await.ok()?;
    build_ctx_from_session(&updated, dry_run).await
}

// ---------------------------------------------------------------------------
// swap_keys
// ---------------------------------------------------------------------------

/// Load another session's credentials into the current AwsContext and verify
/// via STS GetCallerIdentity.
/// Usage: swap_keys <session_name>
pub async fn cmd_swap_keys(
    pool: &SqlitePool,
    session_name: &str,
    dry_run: bool,
) -> Option<AwsContext> {
    if session_name.is_empty() {
        println!("Usage: swap_keys <session_name>");
        return None;
    }

    let sess = match db::load_session(pool, session_name).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} {e}", "swap_keys error:".red().bold());
            return None;
        }
    };

    if sess.access_key_id.is_none() {
        eprintln!(
            "{} session '{}' has no stored credentials.",
            "swap_keys:".red().bold(),
            session_name
        );
        return None;
    }

    let new_ctx = build_ctx_from_session(&sess, dry_run).await?;

    // Verify the new credentials via STS GetCallerIdentity.
    println!(
        "{}",
        "Verifying credentials with STS GetCallerIdentity…".yellow()
    );
    crate::commands::whoami::run(&new_ctx).await;

    Some(new_ctx)
}

// ---------------------------------------------------------------------------
// data
// ---------------------------------------------------------------------------

/// Show cached JSON data from the active session.
/// Usage: data [resource_type]
pub async fn cmd_data(pool: &SqlitePool, resource_type: Option<&str>) {
    let active = match db::get_active_session(pool).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            eprintln!(
                "{}",
                "No active session. Use 'new_session' or 'load_session' first.".red()
            );
            return;
        }
        Err(e) => {
            eprintln!("{} {e}", "get_active_session error:".red().bold());
            return;
        }
    };

    let all_fields: &[(&str, &str)] = &[
        ("iam_users", &active.iam_users),
        ("iam_roles", &active.iam_roles),
        ("iam_groups", &active.iam_groups),
        ("iam_policies", &active.iam_policies),
        ("iam_permissions", &active.iam_permissions),
        ("ec2_instances", &active.ec2_instances),
        ("ec2_security_groups", &active.ec2_security_groups),
        ("ec2_amis", &active.ec2_amis),
        ("ec2_volumes", &active.ec2_volumes),
        ("ec2_snapshots", &active.ec2_snapshots),
        ("s3_buckets", &active.s3_buckets),
        ("lambda_functions", &active.lambda_functions),
        ("extra", &active.extra),
    ];

    match resource_type {
        None => {
            // Print all fields.
            println!(
                "{}  (session: {})",
                "─── Cached data ──────────────────────────────────".cyan(),
                active.name.yellow()
            );
            for (key, val) in all_fields {
                let pretty = pretty_json(val);
                println!("  {}: {}", key.bold(), pretty);
            }
            println!("{}", "──────────────────────────────────────────────────".cyan());
        }
        Some(rt) => {
            match all_fields.iter().find(|(k, _)| *k == rt) {
                None => eprintln!(
                    "{} '{}'. Try one of: {}",
                    "Unknown resource type:".red(),
                    rt,
                    ALL_DATA_FIELDS.join(", ")
                ),
                Some((_, val)) => {
                    println!("{}", pretty_json(val));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// services
// ---------------------------------------------------------------------------

/// Show which resource types have non-empty cached data in the active session.
pub async fn cmd_services(pool: &SqlitePool) {
    let active = match db::get_active_session(pool).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            eprintln!(
                "{}",
                "No active session. Use 'new_session' or 'load_session' first.".red()
            );
            return;
        }
        Err(e) => {
            eprintln!("{} {e}", "get_active_session error:".red().bold());
            return;
        }
    };

    let all_fields = [
        ("iam_users", &active.iam_users),
        ("iam_roles", &active.iam_roles),
        ("iam_groups", &active.iam_groups),
        ("iam_policies", &active.iam_policies),
        ("iam_permissions", &active.iam_permissions),
        ("ec2_instances", &active.ec2_instances),
        ("ec2_security_groups", &active.ec2_security_groups),
        ("ec2_amis", &active.ec2_amis),
        ("ec2_volumes", &active.ec2_volumes),
        ("ec2_snapshots", &active.ec2_snapshots),
        ("s3_buckets", &active.s3_buckets),
        ("lambda_functions", &active.lambda_functions),
        ("extra", &active.extra),
    ];

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Resource Type", "Has Data"]);

    for (key, val) in all_fields {
        let has_data = is_non_empty_json(val);
        let indicator = if has_data {
            "yes".green().bold().to_string()
        } else {
            "-".dimmed().to_string()
        };
        table.add_row(vec![Cell::new(key), Cell::new(indicator)]);
    }
    println!("{table}");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Pretty-print a JSON string, falling back to the raw string on parse failure.
fn pretty_json(raw: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_else(|_| raw.to_owned()),
        Err(_) => raw.to_owned(),
    }
}

/// Return true if the JSON value is a non-empty array or a non-empty object.
fn is_non_empty_json(raw: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(serde_json::Value::Array(arr)) => !arr.is_empty(),
        Ok(serde_json::Value::Object(map)) => !map.is_empty(),
        _ => false,
    }
}

/// Build an AwsContext from stored session credentials, falling back to the
/// default credential chain when the session has no stored keys.
async fn build_ctx_from_session(sess: &db::Session, dry_run: bool) -> Option<AwsContext> {
    if let (Some(ak), Some(sk)) = (&sess.access_key_id, &sess.secret_access_key) {
        let ctx = AwsContext::from_keys(
            ak,
            sk,
            sess.session_token.as_deref(),
            sess.region.as_deref(),
            dry_run,
        )
        .await;
        Some(ctx)
    } else {
        // No credentials stored — return a default-chain context.
        Some(AwsContext::new(dry_run))
    }
}

// ---------------------------------------------------------------------------
// Unit test: set_keys arg parsing logic
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    /// Verify that set_keys correctly extracts ak/sk and optional token from args.
    #[test]
    fn set_keys_parses_args() {
        let args = ["AKIAIOSFODNN7EXAMPLE", "secretkey123", "token-optional"];
        let ak = args[0];
        let sk = args[1];
        let token = args.get(2).copied();

        assert_eq!(ak, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(sk, "secretkey123");
        assert_eq!(token, Some("token-optional"));
    }

    #[test]
    fn set_keys_parses_without_token() {
        let args = ["AKIAIOSFODNN7EXAMPLE", "secretkey123"];
        let ak = args[0];
        let sk = args[1];
        let token: Option<&str> = args.get(2).copied();

        assert_eq!(ak, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(sk, "secretkey123");
        assert!(token.is_none());
    }

    #[test]
    fn set_keys_rejects_too_few_args() {
        let args: &[&str] = &["only-one-arg"];
        assert!(args.len() < 2, "should require at least 2 args");
    }
}
