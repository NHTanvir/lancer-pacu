//! Session struct — maps 1-to-1 with the `sessions` table.
//!
//! SECURITY NOTE: `secret_access_key` is stored in plaintext, matching Pacu's
//! original behaviour. Do NOT commit the sessions.sqlite file to version control.

/// A single Pacu session row fetched from the SQLite database.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub id: i64,
    pub name: String,
    pub created_at: String,
    /// 1 = active, 0 = inactive
    pub active: i64,

    // AWS credentials — plaintext (see security note above)
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    pub key_alias: Option<String>,
    pub region: Option<String>,

    // Cached enumeration data (JSON blobs)
    pub iam_users: String,
    pub iam_roles: String,
    pub iam_groups: String,
    pub iam_policies: String,
    pub iam_permissions: String,

    pub ec2_instances: String,
    pub ec2_security_groups: String,
    pub ec2_amis: String,
    pub ec2_volumes: String,
    pub ec2_snapshots: String,

    pub s3_buckets: String,
    pub lambda_functions: String,

    pub extra: String,
}
