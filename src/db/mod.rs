//! SQLite-backed session management for lancer-pacu.
//!
//! The database file lives at:
//!   Windows  : %APPDATA%\lancer-pacu\sessions.sqlite
//!   Linux/macOS: ~/.local/share/lancer-pacu/sessions.sqlite

// Public DB API — many items are exercised exclusively by tests or future modules.
#![allow(dead_code)]

pub mod session;

pub use session::Session;

use anyhow::{anyhow, Context};
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Whitelist of columns that may be updated via update_session_data.
// This prevents SQL injection through user-supplied column names.
// ---------------------------------------------------------------------------
const ALLOWED_DATA_COLUMNS: &[&str] = &[
    "iam_users",
    "iam_roles",
    "iam_groups",
    "iam_policies",
    "iam_permissions",
    "ec2_instances",
    "ec2_security_groups",
    "ec2_amis",
    "ec2_volumes",
    "ec2_snapshots",
    "s3_buckets",
    "lambda_functions",
    "extra",
];

// ---------------------------------------------------------------------------
// Pool initialisation
// ---------------------------------------------------------------------------

/// Open (or create) the SQLite connection pool and run pending migrations.
pub async fn open_pool() -> anyhow::Result<SqlitePool> {
    let data_dir = dirs::data_dir()
        .ok_or_else(|| anyhow!("cannot determine platform data directory"))?
        .join("lancer-pacu");

    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("failed to create data dir: {}", data_dir.display()))?;

    let db_path = data_dir.join("sessions.sqlite");

    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))?
        .create_if_missing(true);

    let pool = SqlitePool::connect_with(opts).await?;

    // Run embedded migrations from the ./migrations directory (relative to CARGO_MANIFEST_DIR).
    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}

/// Open an in-memory SQLite pool and run migrations. Used for tests.
pub async fn open_pool_memory() -> anyhow::Result<SqlitePool> {
    let pool = SqlitePool::connect("sqlite::memory:").await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

// ---------------------------------------------------------------------------
// Session CRUD
// ---------------------------------------------------------------------------

/// Create a new session with the given name and return it.
/// The session is NOT set as active by default.
pub async fn new_session(pool: &SqlitePool, name: &str) -> anyhow::Result<Session> {
    sqlx::query(
        "INSERT INTO sessions (name) VALUES (?)",
    )
    .bind(name)
    .execute(pool)
    .await
    .with_context(|| format!("failed to create session '{name}'"))?;

    load_session(pool, name).await
}

/// Load an existing session by name.
pub async fn load_session(pool: &SqlitePool, name: &str) -> anyhow::Result<Session> {
    sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow!("session '{name}' not found"))
}

/// Return all sessions ordered by id.
pub async fn list_sessions(pool: &SqlitePool) -> anyhow::Result<Vec<Session>> {
    let sessions = sqlx::query_as::<_, Session>("SELECT * FROM sessions ORDER BY id")
        .fetch_all(pool)
        .await?;
    Ok(sessions)
}

/// Mark one session as active and clear the active flag on all others.
pub async fn set_active_session(pool: &SqlitePool, name: &str) -> anyhow::Result<()> {
    // Verify the session exists first.
    let _session = load_session(pool, name).await?;

    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE sessions SET active = 0")
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE sessions SET active = 1 WHERE name = ?")
        .bind(name)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Return the currently active session, if any.
pub async fn get_active_session(pool: &SqlitePool) -> anyhow::Result<Option<Session>> {
    let session = sqlx::query_as::<_, Session>(
        "SELECT * FROM sessions WHERE active = 1 LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(session)
}

/// Store AWS credentials in a session.
///
/// SECURITY NOTE: `secret_access_key` is stored in plaintext, mirroring
/// Pacu's original behaviour. Keep sessions.sqlite out of version control.
pub async fn update_session_keys(
    pool: &SqlitePool,
    session_id: i64,
    ak: &str,
    sk: &str,
    token: Option<&str>,
    alias: Option<&str>,
    region: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE sessions
         SET access_key_id = ?,
             secret_access_key = ?,
             session_token = ?,
             key_alias = ?,
             region = ?
         WHERE id = ?",
    )
    .bind(ak)
    .bind(sk)
    .bind(token)
    .bind(alias)
    .bind(region)
    .bind(session_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Store a JSON blob in the named enumeration column of a session.
///
/// `column` must be one of the allowed data columns (whitelist enforced to
/// prevent SQL injection).
pub async fn update_session_data(
    pool: &SqlitePool,
    session_id: i64,
    column: &str,
    json_value: &str,
) -> anyhow::Result<()> {
    // Validate the column name against the whitelist.
    if !ALLOWED_DATA_COLUMNS.contains(&column) {
        return Err(anyhow!(
            "'{column}' is not an allowed session data column. \
             Allowed: {}",
            ALLOWED_DATA_COLUMNS.join(", ")
        ));
    }

    // Validate that the value is actually JSON.
    serde_json::from_str::<serde_json::Value>(json_value)
        .with_context(|| format!("value for '{column}' is not valid JSON"))?;

    // Safe to interpolate column name: it passed the whitelist check above.
    let sql = format!("UPDATE sessions SET {column} = ? WHERE id = ?");
    sqlx::query(&sql)
        .bind(json_value)
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    async fn setup() -> SqlitePool {
        open_pool_memory().await.expect("in-memory pool failed")
    }

    #[tokio::test]
    async fn new_session_creates_with_defaults() {
        let pool = setup().await;
        let sess = new_session(&pool, "test-sess").await.unwrap();
        assert_eq!(sess.name, "test-sess");
        assert_eq!(sess.active, 0);
        assert!(sess.access_key_id.is_none());
        assert_eq!(sess.iam_users, "[]");
        assert_eq!(sess.iam_permissions, "{}");
        assert_eq!(sess.extra, "{}");
    }

    #[tokio::test]
    async fn load_session_returns_created() {
        let pool = setup().await;
        new_session(&pool, "alpha").await.unwrap();
        let loaded = load_session(&pool, "alpha").await.unwrap();
        assert_eq!(loaded.name, "alpha");
    }

    #[tokio::test]
    async fn list_sessions_returns_all() {
        let pool = setup().await;
        new_session(&pool, "s1").await.unwrap();
        new_session(&pool, "s2").await.unwrap();
        new_session(&pool, "s3").await.unwrap();
        let all = list_sessions(&pool).await.unwrap();
        assert_eq!(all.len(), 3);
        let names: Vec<&str> = all.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"s1"));
        assert!(names.contains(&"s2"));
        assert!(names.contains(&"s3"));
    }

    #[tokio::test]
    async fn update_session_keys_stores_and_retrieves() {
        let pool = setup().await;
        let sess = new_session(&pool, "key-test").await.unwrap();
        update_session_keys(
            &pool,
            sess.id,
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            Some("token123"),
            Some("my-alias"),
            Some("us-west-2"),
        )
        .await
        .unwrap();

        let updated = load_session(&pool, "key-test").await.unwrap();
        assert_eq!(
            updated.access_key_id.as_deref(),
            Some("AKIAIOSFODNN7EXAMPLE")
        );
        assert_eq!(
            updated.secret_access_key.as_deref(),
            Some("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        );
        assert_eq!(updated.session_token.as_deref(), Some("token123"));
        assert_eq!(updated.key_alias.as_deref(), Some("my-alias"));
        assert_eq!(updated.region.as_deref(), Some("us-west-2"));
    }

    #[tokio::test]
    async fn update_session_data_stores_valid_json() {
        let pool = setup().await;
        let sess = new_session(&pool, "data-test").await.unwrap();
        update_session_data(
            &pool,
            sess.id,
            "iam_users",
            r#"[{"UserName":"alice"},{"UserName":"bob"}]"#,
        )
        .await
        .unwrap();

        let updated = load_session(&pool, "data-test").await.unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&updated.iam_users).unwrap();
        assert_eq!(parsed[0]["UserName"], "alice");
    }

    #[tokio::test]
    async fn update_session_data_rejects_invalid_column() {
        let pool = setup().await;
        let sess = new_session(&pool, "col-test").await.unwrap();
        let result =
            update_session_data(&pool, sess.id, "DROP TABLE sessions", "[]").await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not an allowed session data column"));
    }

    #[tokio::test]
    async fn update_session_data_rejects_invalid_json() {
        let pool = setup().await;
        let sess = new_session(&pool, "json-test").await.unwrap();
        let result =
            update_session_data(&pool, sess.id, "iam_users", "not-json").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn set_active_marks_only_one() {
        let pool = setup().await;
        new_session(&pool, "a").await.unwrap();
        new_session(&pool, "b").await.unwrap();
        set_active_session(&pool, "a").await.unwrap();
        set_active_session(&pool, "b").await.unwrap();

        let active = get_active_session(&pool).await.unwrap();
        assert!(active.is_some());
        assert_eq!(active.unwrap().name, "b");

        let a = load_session(&pool, "a").await.unwrap();
        assert_eq!(a.active, 0);
    }
}
