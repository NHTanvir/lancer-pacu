//! iam__enum_permissions — resolve effective IAM permissions for a principal.
//!
//! For each target principal (user or role) this module:
//!   1. Reads cached IAM data from the session DB (iam_users, iam_roles, iam_groups).
//!   2. Collects attached managed policies and inline policies from AWS.
//!   3. Fetches and parses each policy document.
//!   4. Uses PolicyEvaluator to compute effective Allow / Deny sets.
//!   5. Caches the result to the session DB under `iam_permissions`.
//!   6. Displays a summary table.
//!
//! CLI args:
//!   --principal <arn_or_name>   target a specific user/role ARN or name
//!   --all                       enumerate ALL users and roles in session cache

use anyhow::Context as _;
use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::iam::policy::{parse_policy_document, EffectivePermissions, PolicyEvaluator};
use crate::module::{AwsContext, Module, ModuleInfo};

// ---------------------------------------------------------------------------
// Minimal structs for reading session cache
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CachedUser {
    pub arn: String,
    pub user_name: String,
}

#[derive(Debug, Deserialize)]
struct CachedRole {
    pub arn: String,
    pub role_name: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CachedGroup {
    pub arn: String,
    pub group_name: String,
}

// ---------------------------------------------------------------------------
// Principal kind
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum PrincipalKind {
    User(String),  // user_name
    Role(String),  // role_name
}

#[derive(Debug, Clone)]
struct ResolvedPrincipal {
    arn: String,
    kind: PrincipalKind,
}

// ---------------------------------------------------------------------------
// Serialisable result stored in session DB
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PermissionsMap(pub std::collections::HashMap<String, EffectivePermissions>);

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &AwsContext, args: &[&str]) -> anyhow::Result<()> {
    // ── Parse args ─────────────────────────────────────────────────────────
    let enumerate_all = args.contains(&"--all");
    let principal_arg: Option<&str> = {
        let pos = args.iter().position(|&a| a == "--principal");
        pos.and_then(|i| args.get(i + 1).copied())
    };

    if !enumerate_all && principal_arg.is_none() {
        eprintln!(
            "{}",
            "Usage: run iam__enum_permissions --principal <arn_or_name>  |  --all".yellow()
        );
        return Ok(());
    }

    let iam = aws_sdk_iam::Client::new(&ctx.sdk_config);

    // ── Load cached data from session DB (if available) ────────────────────
    let (cached_users, cached_roles, cached_groups) = load_cached_iam_data(ctx).await;

    // ── Resolve targets ─────────────────────────────────────────────────────
    let targets: Vec<ResolvedPrincipal> = if enumerate_all {
        let mut v: Vec<ResolvedPrincipal> = Vec::new();
        for u in &cached_users {
            v.push(ResolvedPrincipal {
                arn: u.arn.clone(),
                kind: PrincipalKind::User(u.user_name.clone()),
            });
        }
        for r in &cached_roles {
            v.push(ResolvedPrincipal {
                arn: r.arn.clone(),
                kind: PrincipalKind::Role(r.role_name.clone()),
            });
        }
        if v.is_empty() {
            eprintln!(
                "{}",
                "No users or roles in session cache. Run iam__enum_users_roles_policies_groups first.".yellow()
            );
            return Ok(());
        }
        v
    } else {
        let spec = principal_arg.unwrap();
        vec![resolve_principal(spec, &cached_users, &cached_roles)?]
    };

    println!(
        "{}",
        format!("Enumerating permissions for {} principal(s)…", targets.len())
            .cyan()
            .bold()
    );

    // ── Build permissions map (principal_arn → EffectivePermissions) ────────
    let mut perms_map: std::collections::HashMap<String, EffectivePermissions> =
        std::collections::HashMap::new();

    for principal in &targets {
        println!(
            "\n{} {}",
            "→ Processing:".cyan(),
            principal.arn.yellow()
        );

        match process_principal(&iam, principal, &cached_groups).await {
            Ok(perms) => {
                display_principal_summary(&principal.arn, &perms);
                perms_map.insert(principal.arn.clone(), perms);
            }
            Err(e) => {
                eprintln!(
                    "{} {}: {e}",
                    "Warning: failed to enumerate permissions for".yellow(),
                    principal.arn
                );
            }
        }
    }

    // ── Cache to session DB ─────────────────────────────────────────────────
    if let Some(pool) = &ctx.db_pool {
        match crate::db::get_active_session(pool).await {
            Ok(Some(sess)) => {
                // Merge with any existing permissions map.
                let mut existing: std::collections::HashMap<String, EffectivePermissions> =
                    serde_json::from_str(&sess.iam_permissions).unwrap_or_default();
                existing.extend(perms_map);

                let json_val = serde_json::to_string(&existing)?;
                if let Err(e) =
                    crate::db::update_session_data(pool, sess.id, "iam_permissions", &json_val)
                        .await
                {
                    eprintln!("{} {e}", "Warning: could not cache iam_permissions:".yellow());
                } else {
                    println!("{}", "\nPermissions cached to session DB.".green());
                }
            }
            Ok(None) => println!("{}", "No active session — skipping DB cache.".yellow()),
            Err(e) => eprintln!("{} {e}", "Warning: DB error:".yellow()),
        }
    } else {
        println!("{}", "Session DB unavailable — skipping cache.".yellow());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Load cached IAM data from session DB
// ---------------------------------------------------------------------------

async fn load_cached_iam_data(
    ctx: &AwsContext,
) -> (Vec<CachedUser>, Vec<CachedRole>, Vec<CachedGroup>) {
    let Some(pool) = &ctx.db_pool else {
        return (Vec::new(), Vec::new(), Vec::new());
    };

    let Ok(Some(sess)) = crate::db::get_active_session(pool).await else {
        return (Vec::new(), Vec::new(), Vec::new());
    };

    let users: Vec<CachedUser> = serde_json::from_str(&sess.iam_users).unwrap_or_default();
    let roles: Vec<CachedRole> = serde_json::from_str(&sess.iam_roles).unwrap_or_default();
    let groups: Vec<CachedGroup> = serde_json::from_str(&sess.iam_groups).unwrap_or_default();

    (users, roles, groups)
}

// ---------------------------------------------------------------------------
// Resolve a user-provided name/ARN to a ResolvedPrincipal
// ---------------------------------------------------------------------------

fn resolve_principal(
    spec: &str,
    cached_users: &[CachedUser],
    cached_roles: &[CachedRole],
) -> anyhow::Result<ResolvedPrincipal> {
    // If it looks like an ARN, determine kind from it directly.
    if spec.starts_with("arn:aws:iam::") {
        if spec.contains(":user/") {
            let name = spec.rsplit('/').next().unwrap_or(spec).to_owned();
            return Ok(ResolvedPrincipal {
                arn: spec.to_owned(),
                kind: PrincipalKind::User(name),
            });
        }
        if spec.contains(":role/") {
            let name = spec.rsplit('/').next().unwrap_or(spec).to_owned();
            return Ok(ResolvedPrincipal {
                arn: spec.to_owned(),
                kind: PrincipalKind::Role(name),
            });
        }
        anyhow::bail!("ARN '{spec}' is neither a user nor a role ARN");
    }

    // Try to match by name in cached users.
    if let Some(u) = cached_users.iter().find(|u| u.user_name == spec) {
        return Ok(ResolvedPrincipal {
            arn: u.arn.clone(),
            kind: PrincipalKind::User(u.user_name.clone()),
        });
    }

    // Try to match by name in cached roles.
    if let Some(r) = cached_roles.iter().find(|r| r.role_name == spec) {
        return Ok(ResolvedPrincipal {
            arn: r.arn.clone(),
            kind: PrincipalKind::Role(r.role_name.clone()),
        });
    }

    anyhow::bail!(
        "Principal '{spec}' not found in session cache. \
         Run iam__enum_users_roles_policies_groups first, or supply a full ARN."
    )
}

// ---------------------------------------------------------------------------
// Enumerate policies for one principal and evaluate effective permissions
// ---------------------------------------------------------------------------

async fn process_principal(
    iam: &aws_sdk_iam::Client,
    principal: &ResolvedPrincipal,
    _cached_groups: &[CachedGroup],
) -> anyhow::Result<EffectivePermissions> {
    let mut evaluator = PolicyEvaluator::new();

    match &principal.kind {
        PrincipalKind::User(user_name) => {
            // 1a. Attached managed policies for user
            collect_user_attached_managed(iam, user_name, &mut evaluator).await?;

            // 1b. Inline policies for user
            collect_user_inline(iam, user_name, &mut evaluator).await?;

            // 1c. Groups the user belongs to → group policies
            collect_user_group_policies(iam, user_name, &mut evaluator).await?;
        }
        PrincipalKind::Role(role_name) => {
            // 2a. Attached managed policies for role
            collect_role_attached_managed(iam, role_name, &mut evaluator).await?;

            // 2b. Inline policies for role
            collect_role_inline(iam, role_name, &mut evaluator).await?;
        }
    }

    Ok(evaluator.evaluate())
}

// ---------------------------------------------------------------------------
// Policy collection helpers
// ---------------------------------------------------------------------------

/// Fetch and evaluate all managed policies attached to a user.
async fn collect_user_attached_managed(
    iam: &aws_sdk_iam::Client,
    user_name: &str,
    evaluator: &mut PolicyEvaluator,
) -> anyhow::Result<()> {
    let mut paginator = iam
        .list_attached_user_policies()
        .user_name(user_name)
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let page = page.context("iam:ListAttachedUserPolicies failed")?;
        for policy in page.attached_policies() {
            if let Some(arn) = policy.policy_arn() {
                if let Err(e) = fetch_and_add_managed_policy(iam, arn, evaluator).await {
                    eprintln!("  {}: {arn}: {e}", "Warning (managed policy)".yellow());
                }
            }
        }
    }
    Ok(())
}

/// Fetch and evaluate all inline policies attached directly to a user.
async fn collect_user_inline(
    iam: &aws_sdk_iam::Client,
    user_name: &str,
    evaluator: &mut PolicyEvaluator,
) -> anyhow::Result<()> {
    let mut paginator = iam
        .list_user_policies()
        .user_name(user_name)
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let page = page.context("iam:ListUserPolicies failed")?;
        for policy_name in page.policy_names() {
            let resp = iam
                .get_user_policy()
                .user_name(user_name)
                .policy_name(policy_name)
                .send()
                .await
                .context("iam:GetUserPolicy failed")?;

            let raw = resp.policy_document();
            match parse_policy_document(raw) {
                Ok(doc) => evaluator.add_document(doc),
                Err(e) => eprintln!(
                    "  {}: {policy_name}: {e}",
                    "Warning (inline user policy)".yellow()
                ),
            }
        }
    }
    Ok(())
}

/// For each group the user belongs to, collect that group's managed and inline policies.
async fn collect_user_group_policies(
    iam: &aws_sdk_iam::Client,
    user_name: &str,
    evaluator: &mut PolicyEvaluator,
) -> anyhow::Result<()> {
    let mut paginator = iam
        .list_groups_for_user()
        .user_name(user_name)
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let page = page.context("iam:ListGroupsForUser failed")?;
        for group in page.groups() {
            let group_name = group.group_name();

            // Attached managed policies for the group
            let mut gm_paginator = iam
                .list_attached_group_policies()
                .group_name(group_name)
                .into_paginator()
                .send();
            while let Some(gm_page) = gm_paginator.next().await {
                let gm_page = gm_page.context("iam:ListAttachedGroupPolicies failed")?;
                for policy in gm_page.attached_policies() {
                    if let Some(arn) = policy.policy_arn() {
                        if let Err(e) = fetch_and_add_managed_policy(iam, arn, evaluator).await {
                            eprintln!("  {}: {arn}: {e}", "Warning (group managed policy)".yellow());
                        }
                    }
                }
            }

            // Inline policies for the group
            let mut gi_paginator = iam
                .list_group_policies()
                .group_name(group_name)
                .into_paginator()
                .send();
            while let Some(gi_page) = gi_paginator.next().await {
                let gi_page = gi_page.context("iam:ListGroupPolicies failed")?;
                for policy_name in gi_page.policy_names() {
                    let resp = iam
                        .get_group_policy()
                        .group_name(group_name)
                        .policy_name(policy_name)
                        .send()
                        .await
                        .context("iam:GetGroupPolicy failed")?;

                    let raw = resp.policy_document();
                    match parse_policy_document(raw) {
                        Ok(doc) => evaluator.add_document(doc),
                        Err(e) => eprintln!(
                            "  {}: {policy_name}: {e}",
                            "Warning (inline group policy)".yellow()
                        ),
                    }
                }
            }
        }
    }
    Ok(())
}

/// Fetch and evaluate all managed policies attached to a role.
async fn collect_role_attached_managed(
    iam: &aws_sdk_iam::Client,
    role_name: &str,
    evaluator: &mut PolicyEvaluator,
) -> anyhow::Result<()> {
    let mut paginator = iam
        .list_attached_role_policies()
        .role_name(role_name)
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let page = page.context("iam:ListAttachedRolePolicies failed")?;
        for policy in page.attached_policies() {
            if let Some(arn) = policy.policy_arn() {
                if let Err(e) = fetch_and_add_managed_policy(iam, arn, evaluator).await {
                    eprintln!("  {}: {arn}: {e}", "Warning (managed policy)".yellow());
                }
            }
        }
    }
    Ok(())
}

/// Fetch and evaluate all inline policies attached directly to a role.
async fn collect_role_inline(
    iam: &aws_sdk_iam::Client,
    role_name: &str,
    evaluator: &mut PolicyEvaluator,
) -> anyhow::Result<()> {
    let mut paginator = iam
        .list_role_policies()
        .role_name(role_name)
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let page = page.context("iam:ListRolePolicies failed")?;
        for policy_name in page.policy_names() {
            let resp = iam
                .get_role_policy()
                .role_name(role_name)
                .policy_name(policy_name)
                .send()
                .await
                .context("iam:GetRolePolicy failed")?;

            let raw = resp.policy_document();
            match parse_policy_document(raw) {
                Ok(doc) => evaluator.add_document(doc),
                Err(e) => eprintln!(
                    "  {}: {policy_name}: {e}",
                    "Warning (inline role policy)".yellow()
                ),
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Managed policy fetching
// ---------------------------------------------------------------------------

/// Fetch the default version of a managed policy and add its document to the evaluator.
async fn fetch_and_add_managed_policy(
    iam: &aws_sdk_iam::Client,
    policy_arn: &str,
    evaluator: &mut PolicyEvaluator,
) -> anyhow::Result<()> {
    // Get default version ID
    let get_policy_resp = iam
        .get_policy()
        .policy_arn(policy_arn)
        .send()
        .await
        .context("iam:GetPolicy failed")?;

    let version_id = get_policy_resp
        .policy()
        .and_then(|p| p.default_version_id())
        .ok_or_else(|| anyhow::anyhow!("GetPolicy returned no default_version_id"))?
        .to_owned();

    // Get the policy document for that version
    let get_version_resp = iam
        .get_policy_version()
        .policy_arn(policy_arn)
        .version_id(&version_id)
        .send()
        .await
        .context("iam:GetPolicyVersion failed")?;

    let raw = get_version_resp
        .policy_version()
        .and_then(|v| v.document())
        .ok_or_else(|| anyhow::anyhow!("GetPolicyVersion returned no document"))?;

    let doc = parse_policy_document(raw)?;
    evaluator.add_document(doc);
    Ok(())
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

fn display_principal_summary(arn: &str, perms: &EffectivePermissions) {
    println!("\n{} {}", "Principal:".bold(), arn.cyan());

    let allow_preview = if perms.allow.is_empty() {
        "(none)".to_owned()
    } else {
        let preview: Vec<&String> = perms.allow.iter().take(10).collect();
        let s = preview
            .iter()
            .map(|a| a.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if perms.allow.len() > 10 {
            format!("{s}, …")
        } else {
            s
        }
    };

    let deny_preview = if perms.deny.is_empty() {
        "(none)".to_owned()
    } else {
        perms.deny.join(", ")
    };

    println!(
        "  {} ({:>3}): {}",
        "Allow".green().bold(),
        perms.allow.len(),
        allow_preview.green()
    );
    println!(
        "  {}  ({:>3}): {}",
        "Deny".red().bold(),
        perms.deny.len(),
        deny_preview.red()
    );
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

inventory::submit! {
    Module {
        info: ModuleInfo {
            name: "iam__enum_permissions",
            author: "lancer-pacu",
            category: "ENUM",
            one_liner: "Resolve effective IAM permissions for a user or role.",
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
            .any(|m| m.info.name == "iam__enum_permissions");
        assert!(found, "iam__enum_permissions not found in inventory");
    }

    /// Inventory has at least 4 modules after this module is added.
    #[test]
    fn inventory_has_at_least_four_modules() {
        let count = inventory::iter::<Module>.into_iter().count();
        assert!(
            count >= 4,
            "expected at least 4 modules in inventory, found {count}"
        );
    }

    /// resolve_principal correctly picks a user from cache by name.
    #[test]
    fn resolve_user_by_name() {
        let users = vec![CachedUser {
            user_name: "alice".to_owned(),
            arn: "arn:aws:iam::123456789012:user/alice".to_owned(),
        }];
        let roles: Vec<CachedRole> = vec![];
        let resolved = resolve_principal("alice", &users, &roles).unwrap();
        assert_eq!(resolved.arn, "arn:aws:iam::123456789012:user/alice");
        assert!(matches!(resolved.kind, PrincipalKind::User(_)));
    }

    /// resolve_principal correctly picks a role from cache by name.
    #[test]
    fn resolve_role_by_name() {
        let users: Vec<CachedUser> = vec![];
        let roles = vec![CachedRole {
            role_name: "MyRole".to_owned(),
            arn: "arn:aws:iam::123456789012:role/MyRole".to_owned(),
        }];
        let resolved = resolve_principal("MyRole", &users, &roles).unwrap();
        assert_eq!(resolved.arn, "arn:aws:iam::123456789012:role/MyRole");
        assert!(matches!(resolved.kind, PrincipalKind::Role(_)));
    }

    /// resolve_principal accepts a full user ARN without cache lookup.
    #[test]
    fn resolve_user_by_full_arn() {
        let users: Vec<CachedUser> = vec![];
        let roles: Vec<CachedRole> = vec![];
        let arn = "arn:aws:iam::999999999999:user/bob";
        let resolved = resolve_principal(arn, &users, &roles).unwrap();
        assert_eq!(resolved.arn, arn);
        assert!(matches!(resolved.kind, PrincipalKind::User(_)));
    }

    /// resolve_principal accepts a full role ARN without cache lookup.
    #[test]
    fn resolve_role_by_full_arn() {
        let users: Vec<CachedUser> = vec![];
        let roles: Vec<CachedRole> = vec![];
        let arn = "arn:aws:iam::999999999999:role/SomeRole";
        let resolved = resolve_principal(arn, &users, &roles).unwrap();
        assert_eq!(resolved.arn, arn);
        assert!(matches!(resolved.kind, PrincipalKind::Role(_)));
    }

    /// resolve_principal returns an error for an unknown name not in cache.
    #[test]
    fn resolve_unknown_name_fails() {
        let users: Vec<CachedUser> = vec![];
        let roles: Vec<CachedRole> = vec![];
        let result = resolve_principal("nonexistent", &users, &roles);
        assert!(result.is_err());
    }

    /// PermissionsMap serialises and deserialises correctly.
    #[test]
    fn permissions_map_round_trip() {
        let mut map = std::collections::HashMap::new();
        map.insert(
            "arn:aws:iam::123:user/alice".to_owned(),
            EffectivePermissions {
                allow: vec!["s3:getobject".to_owned()],
                deny: vec!["iam:deletepolicy".to_owned()],
            },
        );
        let json = serde_json::to_string(&map).unwrap();
        let back: std::collections::HashMap<String, EffectivePermissions> =
            serde_json::from_str(&json).unwrap();
        let perms = back.get("arn:aws:iam::123:user/alice").unwrap();
        assert!(perms.allow.contains(&"s3:getobject".to_owned()));
        assert!(perms.deny.contains(&"iam:deletepolicy".to_owned()));
    }
}
