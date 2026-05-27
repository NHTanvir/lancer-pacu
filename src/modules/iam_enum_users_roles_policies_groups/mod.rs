//! iam__enum_users_roles_policies_groups — paginate IAM users, roles,
//! groups, and customer-managed policies then cache to the session DB.
//!
//! Calls:
//!   - iam:ListUsers      (paginated)
//!   - iam:ListRoles      (paginated)
//!   - iam:ListGroups     (paginated)
//!   - iam:ListPolicies   (paginated, scope = Local)

use anyhow::Context as _;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Helper: format an aws_smithy_types::DateTime to an ISO string
// ---------------------------------------------------------------------------

fn fmt_datetime(dt: &aws_sdk_iam::primitives::DateTime) -> String {
    dt.fmt(aws_sdk_iam::primitives::DateTimeFormat::DateTime)
        .unwrap_or_else(|_| "<invalid-date>".to_owned())
}

// ---------------------------------------------------------------------------
// Serialisable structs (pub for test access)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct IamUser {
    pub user_name: String,
    pub user_id: String,
    pub arn: String,
    pub create_date: Option<String>,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IamRole {
    pub role_name: String,
    pub role_id: String,
    pub arn: String,
    pub create_date: Option<String>,
    pub path: String,
    pub assume_role_policy_document: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IamGroup {
    pub group_name: String,
    pub group_id: String,
    pub arn: String,
    pub create_date: Option<String>,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IamPolicy {
    pub policy_name: String,
    pub policy_id: String,
    pub arn: String,
    pub attachment_count: i32,
    pub create_date: Option<String>,
}

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, _args: &[&str]) -> anyhow::Result<()> {
    let iam = aws_sdk_iam::Client::new(&ctx.sdk_config);

    // ── 1. List Users ──────────────────────────────────────────────────────
    let mut users: Vec<IamUser> = Vec::new();
    {
        let mut paginator = iam.list_users().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let page = page.context("iam:ListUsers page failed")?;
            for user in page.users() {
                users.push(IamUser {
                    user_name: user.user_name().to_owned(),
                    user_id:   user.user_id().to_owned(),
                    arn:       user.arn().to_owned(),
                    // create_date() returns &DateTime (non-optional) for User
                    create_date: Some(fmt_datetime(user.create_date())),
                    path:      user.path().to_owned(),
                });
            }
        }
    }

    // ── 2. List Roles ──────────────────────────────────────────────────────
    let mut roles: Vec<IamRole> = Vec::new();
    {
        let mut paginator = iam.list_roles().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let page = page.context("iam:ListRoles page failed")?;
            for role in page.roles() {
                roles.push(IamRole {
                    role_name: role.role_name().to_owned(),
                    role_id:   role.role_id().to_owned(),
                    arn:       role.arn().to_owned(),
                    create_date: Some(fmt_datetime(role.create_date())),
                    path:      role.path().to_owned(),
                    assume_role_policy_document: role
                        .assume_role_policy_document()
                        .map(|s| s.to_owned()),
                });
            }
        }
    }

    // ── 3. List Groups ─────────────────────────────────────────────────────
    let mut groups: Vec<IamGroup> = Vec::new();
    {
        let mut paginator = iam.list_groups().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let page = page.context("iam:ListGroups page failed")?;
            for group in page.groups() {
                groups.push(IamGroup {
                    group_name: group.group_name().to_owned(),
                    group_id:   group.group_id().to_owned(),
                    arn:        group.arn().to_owned(),
                    create_date: Some(fmt_datetime(group.create_date())),
                    path:       group.path().to_owned(),
                });
            }
        }
    }

    // ── 4. List Policies (scope = Local = customer-managed) ────────────────
    let mut policies: Vec<IamPolicy> = Vec::new();
    {
        let mut paginator = iam
            .list_policies()
            .scope(aws_sdk_iam::types::PolicyScopeType::Local)
            .into_paginator()
            .send();
        while let Some(page) = paginator.next().await {
            let page = page.context("iam:ListPolicies page failed")?;
            for policy in page.policies() {
                policies.push(IamPolicy {
                    policy_name: policy.policy_name().unwrap_or("<unnamed>").to_owned(),
                    policy_id:   policy.policy_id().unwrap_or("").to_owned(),
                    arn:         policy.arn().unwrap_or("").to_owned(),
                    attachment_count: policy.attachment_count().unwrap_or(0),
                    create_date: policy
                        .create_date()
                        .map(fmt_datetime),
                });
            }
        }
    }

    // ── 5. Print summary ───────────────────────────────────────────────────
    println!(
        "{}",
        format!(
            "Enumerated {} users, {} roles, {} groups, {} policies",
            users.len(),
            roles.len(),
            groups.len(),
            policies.len()
        )
        .green()
        .bold()
    );

    // ── 6. Cache to session DB ─────────────────────────────────────────────
    if let Some(pool) = &ctx.db_pool {
        match crate::db::get_active_session(pool).await {
            Ok(Some(sess)) => {
                let cache_pairs: &[(&str, serde_json::Value)] = &[
                    ("iam_users",    json!(users)),
                    ("iam_roles",    json!(roles)),
                    ("iam_groups",   json!(groups)),
                    ("iam_policies", json!(policies)),
                ];
                for (column, value) in cache_pairs {
                    if let Err(e) = crate::db::update_session_data(
                        pool,
                        sess.id,
                        column,
                        &value.to_string(),
                    )
                    .await
                    {
                        eprintln!(
                            "{} {e}",
                            format!("Warning: could not cache {column}:").yellow()
                        );
                    }
                }
                println!("{}", "IAM data cached to session DB.".green());
            }
            Ok(None) => {
                println!("{}", "No active session — skipping DB cache.".yellow());
            }
            Err(e) => {
                eprintln!("{} {e}", "Warning: DB error:".yellow());
            }
        }
    } else {
        println!("{}", "Session DB unavailable — skipping cache.".yellow());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "iam__enum_users_roles_policies_groups",
            author: "lancer-pacu",
            category: "ENUM",
            one_liner: "Enumerate IAM users, roles, policies, and groups.",
            services: &["IAM"],
        },
        run: |ctx, args| Box::pin(run(ctx, args)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::Module;

    /// Module is registered in the inventory.
    #[test]
    fn module_registered_in_inventory() {
        let found = inventory::iter::<Module>
            .into_iter()
            .any(|m| m.info.name == "iam__enum_users_roles_policies_groups");
        assert!(found, "iam__enum_users_roles_policies_groups not found in inventory");
    }

    /// Struct serialisation round-trip for IamUser.
    #[test]
    fn iam_user_serialises() {
        let u = IamUser {
            user_name: "alice".to_owned(),
            user_id: "AIDA000000000000".to_owned(),
            arn: "arn:aws:iam::123456789012:user/alice".to_owned(),
            create_date: Some("2024-01-01T00:00:00Z".to_owned()),
            path: "/".to_owned(),
        };
        let json = serde_json::to_string(&u).unwrap();
        let back: IamUser = serde_json::from_str(&json).unwrap();
        assert_eq!(back.user_name, "alice");
        assert_eq!(back.user_id, "AIDA000000000000");
    }

    /// Struct serialisation round-trip for IamRole.
    #[test]
    fn iam_role_serialises() {
        let r = IamRole {
            role_name: "MyRole".to_owned(),
            role_id: "AROA000000000000".to_owned(),
            arn: "arn:aws:iam::123456789012:role/MyRole".to_owned(),
            create_date: Some("2024-01-01T00:00:00Z".to_owned()),
            path: "/".to_owned(),
            assume_role_policy_document: Some(r#"{"Version":"2012-10-17"}"#.to_owned()),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: IamRole = serde_json::from_str(&json).unwrap();
        assert_eq!(back.role_name, "MyRole");
        assert_eq!(back.assume_role_policy_document.as_deref(), Some(r#"{"Version":"2012-10-17"}"#));
    }

    /// Struct serialisation round-trip for IamGroup.
    #[test]
    fn iam_group_serialises() {
        let g = IamGroup {
            group_name: "admins".to_owned(),
            group_id: "AGPA000000000000".to_owned(),
            arn: "arn:aws:iam::123456789012:group/admins".to_owned(),
            create_date: Some("2024-01-01T00:00:00Z".to_owned()),
            path: "/".to_owned(),
        };
        let json = serde_json::to_string(&g).unwrap();
        let back: IamGroup = serde_json::from_str(&json).unwrap();
        assert_eq!(back.group_name, "admins");
    }

    /// Struct serialisation round-trip for IamPolicy.
    #[test]
    fn iam_policy_serialises() {
        let p = IamPolicy {
            policy_name: "MyPolicy".to_owned(),
            policy_id: "ANPA000000000000".to_owned(),
            arn: "arn:aws:iam::123456789012:policy/MyPolicy".to_owned(),
            attachment_count: 3,
            create_date: Some("2024-01-01T00:00:00Z".to_owned()),
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: IamPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.policy_name, "MyPolicy");
        assert_eq!(back.attachment_count, 3);
    }
}
