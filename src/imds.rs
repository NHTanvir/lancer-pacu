//! IMDSv2 credential fetching for in-instance use.
//!
//! This module fetches temporary AWS credentials from the EC2 Instance Metadata
//! Service v2 (IMDSv2), which requires a session token obtained via a PUT request.
//!
//! Flow:
//!   1. PUT  /latest/api/token                              → session token
//!   2. GET  /latest/meta-data/iam/security-credentials/   → role name
//!   3. GET  /latest/meta-data/iam/security-credentials/<role> → credentials JSON

use anyhow::{bail, Context};
use serde::Deserialize;

const IMDS_BASE: &str = "http://169.254.169.254";
const TOKEN_TTL_SECONDS: &str = "21600"; // 6 hours

/// Temporary credentials returned by IMDSv2.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImdsCredentials {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,
    #[serde(rename = "Token")]
    pub token: String,
    #[serde(rename = "Expiration")]
    pub expiration: String,
    /// The IAM role name associated with these credentials.
    #[serde(skip)]
    pub role: String,
}

/// Fetch temporary credentials from IMDSv2.
///
/// Requires the binary to be running on an EC2 instance with an attached
/// IAM instance profile. Returns an error if IMDS is unreachable.
pub async fn fetch_imds_credentials() -> anyhow::Result<ImdsCredentials> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .context("failed to build HTTP client")?;

    // Step 1: get IMDSv2 token.
    let token = client
        .put(format!("{IMDS_BASE}/latest/api/token"))
        .header("X-aws-ec2-metadata-token-ttl-seconds", TOKEN_TTL_SECONDS)
        .send()
        .await
        .context("failed to PUT IMDSv2 token endpoint (is this an EC2 instance?)")?
        .error_for_status()
        .context("IMDSv2 token endpoint returned an error")?
        .text()
        .await
        .context("failed to read token response body")?;

    // Step 2: get the role name.
    let role_list = client
        .get(format!(
            "{IMDS_BASE}/latest/meta-data/iam/security-credentials/"
        ))
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .await
        .context("failed to GET IAM security-credentials list")?
        .error_for_status()
        .context("IAM security-credentials list endpoint returned an error")?
        .text()
        .await
        .context("failed to read role list body")?;

    let role = role_list
        .lines()
        .next()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("no IAM role attached to this instance"))?;

    if role.is_empty() {
        bail!("no IAM role attached to this instance");
    }

    // Step 3: fetch credentials for the role.
    let creds_json = client
        .get(format!(
            "{IMDS_BASE}/latest/meta-data/iam/security-credentials/{role}"
        ))
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .await
        .context("failed to GET IAM credentials")?
        .error_for_status()
        .context("IAM credentials endpoint returned an error")?
        .text()
        .await
        .context("failed to read credentials body")?;

    let mut creds: ImdsCredentials =
        serde_json::from_str(&creds_json).context("failed to parse IMDS credentials JSON")?;
    creds.role = role;

    Ok(creds)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::ImdsCredentials;

    /// Verify that ImdsCredentials can be constructed (struct is sound).
    #[test]
    fn imds_credentials_struct_is_constructible() {
        let creds = ImdsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_owned(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_owned(),
            token: "AQoXnyc4lcK4w4OIaHaLmgem…".to_owned(),
            expiration: "2026-01-01T00:00:00Z".to_owned(),
            role: "my-ec2-role".to_owned(),
        };
        assert_eq!(creds.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(creds.role, "my-ec2-role");
    }

    /// Verify JSON deserialization from a realistic IMDS payload.
    #[test]
    fn imds_credentials_deserializes_from_json() {
        let json = r#"{
            "Code": "Success",
            "LastUpdated": "2026-01-01T00:00:00Z",
            "Type": "AWS-HMAC",
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "Token": "AQoXnyc4lcK4w==",
            "Expiration": "2026-01-01T06:00:00Z"
        }"#;
        let creds: ImdsCredentials = serde_json::from_str(json).unwrap();
        assert_eq!(creds.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(creds.expiration, "2026-01-01T06:00:00Z");
        // `role` is skipped in JSON — defaults to empty string
        assert_eq!(creds.role, "");
    }
}
