//! Proxy management REPL commands: set_proxy, proxy, clear_proxy.
//!
//! Stores the proxy URL in the active session's `extra` JSON field under the
//! key "proxy".
//!
//! # Full SDK integration note
//!
//! Wiring a SOCKS5 proxy into the AWS SDK requires a custom tower middleware /
//! connector that intercepts hyper's transport layer and routes it through the
//! SOCKS5 handshake (e.g. via `tokio-socks`). This is non-trivial and is
//! intentionally deferred. The `tokio-socks` crate is included in Cargo.toml
//! and can be leveraged when building the custom connector in a future task.
//!
//! For now this module provides the storage and display layer so that proxy
//! settings persist across sessions and are visible to the user.

use colored::Colorize;
use sqlx::SqlitePool;

use crate::db;

// ---------------------------------------------------------------------------
// set_proxy
// ---------------------------------------------------------------------------

/// Store a SOCKS5 proxy URL in the active session's `extra` field.
///
/// Usage: `set_proxy socks5://host:port`
pub async fn cmd_set_proxy(pool: &SqlitePool, args: &[&str]) {
    let url = match args.first().copied() {
        Some(u) => u,
        None => {
            println!("Usage: set_proxy <socks5://host:port>");
            return;
        }
    };

    // Basic validation — must start with socks5://
    if !url.starts_with("socks5://") {
        eprintln!(
            "{}",
            "set_proxy: URL must start with socks5:// (e.g. socks5://127.0.0.1:1080)".red()
        );
        return;
    }

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

    // Merge the proxy URL into the existing `extra` JSON object.
    let mut extra: serde_json::Value =
        serde_json::from_str(&active.extra).unwrap_or_else(|_| serde_json::json!({}));

    if let Some(obj) = extra.as_object_mut() {
        obj.insert("proxy".to_owned(), serde_json::Value::String(url.to_owned()));
    }

    let extra_str = serde_json::to_string(&extra).unwrap_or_else(|_| "{}".to_owned());

    if let Err(e) = db::update_session_data(pool, active.id, "extra", &extra_str).await {
        eprintln!("{} {e}", "set_proxy: failed to save proxy:".red().bold());
        return;
    }

    println!(
        "{} {}",
        "Proxy set:".green().bold(),
        url.cyan()
    );
    println!(
        "{}",
        "Note: full AWS SDK proxy routing requires a custom connector (deferred).".yellow()
    );
}

// ---------------------------------------------------------------------------
// proxy (show current)
// ---------------------------------------------------------------------------

/// Display the currently configured proxy for the active session.
pub async fn cmd_show_proxy(pool: &SqlitePool) {
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

    let extra: serde_json::Value =
        serde_json::from_str(&active.extra).unwrap_or_else(|_| serde_json::json!({}));

    match extra.get("proxy").and_then(|v| v.as_str()) {
        Some(proxy) => println!("Current proxy: {}", proxy.cyan()),
        None => println!("{}", "No proxy configured. Use: set_proxy socks5://host:port".yellow()),
    }
}

// ---------------------------------------------------------------------------
// clear_proxy
// ---------------------------------------------------------------------------

/// Remove the proxy setting from the active session.
pub async fn cmd_clear_proxy(pool: &SqlitePool) {
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

    let mut extra: serde_json::Value =
        serde_json::from_str(&active.extra).unwrap_or_else(|_| serde_json::json!({}));

    let removed = if let Some(obj) = extra.as_object_mut() {
        obj.remove("proxy").is_some()
    } else {
        false
    };

    let extra_str = serde_json::to_string(&extra).unwrap_or_else(|_| "{}".to_owned());

    if let Err(e) = db::update_session_data(pool, active.id, "extra", &extra_str).await {
        eprintln!("{} {e}", "clear_proxy: failed to save:".red().bold());
        return;
    }

    if removed {
        println!("{}", "Proxy cleared.".green().bold());
    } else {
        println!("{}", "No proxy was set.".yellow());
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn set_proxy_stores_in_session_extra() {
        let pool = crate::db::open_pool_memory().await.unwrap();
        crate::db::new_session(&pool, "proxy-test").await.unwrap();
        crate::db::set_active_session(&pool, "proxy-test").await.unwrap();

        cmd_set_proxy(&pool, &["socks5://127.0.0.1:1080"]).await;

        let sess = crate::db::load_session(&pool, "proxy-test").await.unwrap();
        let extra: serde_json::Value = serde_json::from_str(&sess.extra).unwrap();
        assert_eq!(extra["proxy"], "socks5://127.0.0.1:1080");
    }

    #[tokio::test]
    async fn clear_proxy_removes_from_session_extra() {
        let pool = crate::db::open_pool_memory().await.unwrap();
        crate::db::new_session(&pool, "proxy-clear-test").await.unwrap();
        crate::db::set_active_session(&pool, "proxy-clear-test").await.unwrap();

        // Set then clear.
        cmd_set_proxy(&pool, &["socks5://10.0.0.1:9050"]).await;
        cmd_clear_proxy(&pool).await;

        let sess = crate::db::load_session(&pool, "proxy-clear-test").await.unwrap();
        let extra: serde_json::Value = serde_json::from_str(&sess.extra).unwrap();
        assert!(extra.get("proxy").is_none());
    }

    #[tokio::test]
    async fn set_proxy_rejects_non_socks5_url() {
        // No crash expected — just prints error message and returns.
        let pool = crate::db::open_pool_memory().await.unwrap();
        crate::db::new_session(&pool, "proxy-bad-url").await.unwrap();
        crate::db::set_active_session(&pool, "proxy-bad-url").await.unwrap();

        // http:// is not a valid SOCKS5 URL — should not update extra.
        cmd_set_proxy(&pool, &["http://proxy.example.com:8080"]).await;

        let sess = crate::db::load_session(&pool, "proxy-bad-url").await.unwrap();
        let extra: serde_json::Value = serde_json::from_str(&sess.extra).unwrap();
        assert!(extra.get("proxy").is_none());
    }
}
