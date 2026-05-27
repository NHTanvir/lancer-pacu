//! IAM privilege escalation path definitions and detection logic.
//!
//! Defines all 25 known IAM privilege escalation paths and provides
//! helper functions to detect which paths are exploitable given a
//! principal's effective permissions.

use crate::iam::policy::EffectivePermissions;

// ---------------------------------------------------------------------------
// PrivescPath definition
// ---------------------------------------------------------------------------

/// A single IAM privilege escalation path definition.
#[derive(Debug)]
pub struct PrivescPath {
    pub id: u8,
    pub name: &'static str,
    /// Normalized lowercase IAM permissions required to exploit this path.
    pub required_perms: &'static [&'static str],
    /// Human-readable note on how this path shows up in CloudTrail.
    pub detection_note: &'static str,
}

/// All 25 known IAM privilege escalation paths.
pub const PRIVESC_PATHS: &[PrivescPath] = &[
    PrivescPath {
        id: 1,
        name: "CreatePolicyVersion",
        required_perms: &["iam:createpolicyversion"],
        detection_note: "CloudTrail CreatePolicyVersion with SetAsDefault=true",
    },
    PrivescPath {
        id: 2,
        name: "SetDefaultPolicyVersion",
        required_perms: &["iam:setdefaultpolicyversion"],
        detection_note: "SetDefaultPolicyVersion from low-priv principal",
    },
    PrivescPath {
        id: 3,
        name: "EC2RunInstancesWithPassRole",
        required_perms: &["iam:passrole", "ec2:runinstances"],
        detection_note: "RunInstances with IamInstanceProfile to admin role",
    },
    PrivescPath {
        id: 4,
        name: "CreateAccessKeyOnOtherUser",
        required_perms: &["iam:createaccesskey"],
        detection_note: "CreateAccessKey where caller != target user",
    },
    PrivescPath {
        id: 5,
        name: "CreateLoginProfile",
        required_perms: &["iam:createloginprofile"],
        detection_note: "CreateLoginProfile where caller != target",
    },
    PrivescPath {
        id: 6,
        name: "UpdateLoginProfile",
        required_perms: &["iam:updateloginprofile"],
        detection_note: "UpdateLoginProfile where caller != target",
    },
    PrivescPath {
        id: 7,
        name: "AttachUserPolicy",
        required_perms: &["iam:attachuserpolicy"],
        detection_note: "AttachUserPolicy of AdministratorAccess or wildcard policy",
    },
    PrivescPath {
        id: 8,
        name: "AttachGroupPolicy",
        required_perms: &["iam:attachgrouppolicy"],
        detection_note: "AttachGroupPolicy to caller's group",
    },
    PrivescPath {
        id: 9,
        name: "AttachRolePolicy",
        required_perms: &["iam:attachrolepolicy", "sts:assumerole"],
        detection_note: "Attach admin policy to assumable role",
    },
    PrivescPath {
        id: 10,
        name: "PutUserPolicy",
        required_perms: &["iam:putuserpolicy"],
        detection_note: "Inline policy with Action:* Resource:*",
    },
    PrivescPath {
        id: 11,
        name: "PutGroupPolicy",
        required_perms: &["iam:putgrouppolicy"],
        detection_note: "Same on group",
    },
    PrivescPath {
        id: 12,
        name: "PutRolePolicy",
        required_perms: &["iam:putrolepolicy", "sts:assumerole"],
        detection_note: "Same on role",
    },
    PrivescPath {
        id: 13,
        name: "AddUserToGroup",
        required_perms: &["iam:addusertogroup"],
        detection_note: "AddUserToGroup into privileged group",
    },
    PrivescPath {
        id: 14,
        name: "UpdateAssumeRolePolicy",
        required_perms: &["iam:updateassumerolepolicy", "sts:assumerole"],
        detection_note: "Trust policy added a new principal",
    },
    PrivescPath {
        id: 15,
        name: "LambdaCreateFunctionInvoke",
        required_perms: &["iam:passrole", "lambda:createfunction", "lambda:invokefunction"],
        detection_note: "New Lambda with admin role + Invoke from suspect IP",
    },
    PrivescPath {
        id: 16,
        name: "LambdaDynamoDBEventSource",
        required_perms: &[
            "iam:passrole",
            "lambda:createfunction",
            "lambda:createeventsourcemapping",
            "dynamodb:createtable",
        ],
        detection_note: "EventSourceMapping created against attacker-controlled table",
    },
    PrivescPath {
        id: 17,
        name: "UpdateExistingLambdaCode",
        required_perms: &["lambda:updatefunctioncode"],
        detection_note: "UpdateFunctionCode followed by abnormal invocation",
    },
    PrivescPath {
        id: 18,
        name: "GlueCreateDevEndpoint",
        required_perms: &["iam:passrole", "glue:createdevendpoint"],
        detection_note: "CreateDevEndpoint with privileged role + SSH key",
    },
    PrivescPath {
        id: 19,
        name: "GlueUpdateDevEndpoint",
        required_perms: &["glue:updatedevendpoint"],
        detection_note: "SSH public key replaced on existing endpoint",
    },
    PrivescPath {
        id: 20,
        name: "CloudFormationCreateStack",
        required_perms: &["iam:passrole", "cloudformation:createstack"],
        detection_note: "CreateStack with role that has more privs than caller",
    },
    PrivescPath {
        id: 21,
        name: "DataPipelinePassRole",
        required_perms: &[
            "iam:passrole",
            "datapipeline:createpipeline",
            "datapipeline:putpipelinedefinition",
        ],
        detection_note: "CreatePipeline → PutDefinition → ActivatePipeline",
    },
    PrivescPath {
        id: 22,
        name: "SSMSendCommandWithPassRole",
        required_perms: &["iam:passrole", "ssm:sendcommand"],
        detection_note: "SSM SendCommand with PassRole on EC2 instance profile → RCE",
    },
    PrivescPath {
        id: 23,
        name: "CodeBuildCreateProjectWithPassRole",
        required_perms: &["iam:passrole", "codebuild:createproject"],
        detection_note: "Execute buildspec as service role",
    },
    PrivescPath {
        id: 24,
        name: "SageMakerCreateNotebookWithPassRole",
        required_perms: &["iam:passrole", "sagemaker:createnotebookinstance"],
        detection_note: "SageMaker notebook with privileged execution role",
    },
    PrivescPath {
        id: 25,
        name: "EventBridgePutRuleWithPassRole",
        required_perms: &["iam:passrole", "events:putrule", "events:puttargets"],
        detection_note: "EventBridge PutRule → Lambda Invoke with PassRole",
    },
];

// ---------------------------------------------------------------------------
// Permission matching
// ---------------------------------------------------------------------------

/// Returns true if `allow` contains the specific `required` permission,
/// accounting for service-level wildcards (`iam:*`) and the global wildcard (`*`).
pub fn has_permission(allow: &[String], required: &str) -> bool {
    // exact match
    if allow.contains(&required.to_string()) {
        return true;
    }
    // service wildcard: "iam:*" matches "iam:createpolicyversion"
    if let Some((service, _)) = required.split_once(':') {
        let wildcard = format!("{}:*", service);
        if allow.contains(&wildcard) {
            return true;
        }
    }
    // global wildcard
    if allow.contains(&"*".to_string()) {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Scan result
// ---------------------------------------------------------------------------

/// The result of scanning a principal's permissions for escalation paths.
pub struct ScanResult {
    pub principal_arn: String,
    pub vulnerable_paths: Vec<&'static PrivescPath>,
}

/// Scan a principal's effective permissions and return all exploitable paths.
pub fn scan_principal(
    principal_arn: String,
    effective: &EffectivePermissions,
) -> ScanResult {
    let vulnerable_paths: Vec<&'static PrivescPath> = PRIVESC_PATHS
        .iter()
        .filter(|path| {
            path.required_perms
                .iter()
                .all(|req| has_permission(&effective.allow, req))
        })
        .collect();

    ScanResult {
        principal_arn,
        vulnerable_paths,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::iam::policy::EffectivePermissions;

    fn allow(perms: &[&str]) -> Vec<String> {
        perms.iter().map(|s| s.to_string()).collect()
    }

    fn make_effective(allow_perms: &[&str]) -> EffectivePermissions {
        EffectivePermissions {
            allow: allow(allow_perms),
            deny: vec![],
        }
    }

    // ── has_permission tests ───────────────────────────────────────────────

    #[test]
    fn has_permission_exact_match() {
        let allow_list = allow(&["iam:attachuserpolicy", "s3:getobject"]);
        assert!(has_permission(&allow_list, "iam:attachuserpolicy"));
    }

    #[test]
    fn has_permission_service_wildcard() {
        let allow_list = allow(&["iam:*"]);
        assert!(has_permission(&allow_list, "iam:createpolicyversion"));
        assert!(has_permission(&allow_list, "iam:attachuserpolicy"));
        // different service should not match
        assert!(!has_permission(&allow_list, "s3:getobject"));
    }

    #[test]
    fn has_permission_global_wildcard() {
        let allow_list = allow(&["*"]);
        assert!(has_permission(&allow_list, "iam:createpolicyversion"));
        assert!(has_permission(&allow_list, "s3:getobject"));
        assert!(has_permission(&allow_list, "ec2:runinstances"));
    }

    #[test]
    fn has_permission_no_match() {
        let allow_list = allow(&["s3:getobject", "ec2:describeinstances"]);
        assert!(!has_permission(&allow_list, "iam:attachuserpolicy"));
    }

    // ── scan_principal tests ───────────────────────────────────────────────

    #[test]
    fn scan_with_attach_user_policy_finds_path_7() {
        let effective = make_effective(&["iam:attachuserpolicy"]);
        let result = scan_principal(
            "arn:aws:iam::123456789012:user/alice".to_owned(),
            &effective,
        );
        let ids: Vec<u8> = result.vulnerable_paths.iter().map(|p| p.id).collect();
        assert!(
            ids.contains(&7),
            "Expected path 7 (AttachUserPolicy) to be found, got: {ids:?}"
        );
    }

    #[test]
    fn scan_with_no_permissions_finds_nothing() {
        let effective = make_effective(&[]);
        let result = scan_principal(
            "arn:aws:iam::123456789012:user/nobody".to_owned(),
            &effective,
        );
        assert!(
            result.vulnerable_paths.is_empty(),
            "Expected no vulnerable paths, found: {}",
            result.vulnerable_paths.len()
        );
    }

    #[test]
    fn scan_with_iam_wildcard_finds_all_iam_paths() {
        // iam:* plus sts:assumerole so that multi-perm iam+sts paths are also caught.
        // Path 3 (EC2RunInstancesWithPassRole) also requires ec2:runinstances, so
        // add that too to make this a comprehensive iam-wildcard test.
        let effective = make_effective(&["iam:*", "sts:assumerole", "ec2:runinstances"]);
        let result = scan_principal(
            "arn:aws:iam::123456789012:user/admin".to_owned(),
            &effective,
        );

        // All paths whose required_perms are entirely within iam:*, sts:assumerole,
        // or ec2:runinstances should be found — that covers paths 1-14.
        let ids: Vec<u8> = result.vulnerable_paths.iter().map(|p| p.id).collect();
        for id in 1u8..=14 {
            assert!(
                ids.contains(&id),
                "Expected path {id} to be vulnerable with iam:* + sts:assumerole + ec2:runinstances, got: {ids:?}"
            );
        }
    }

    #[test]
    fn privesc_paths_has_exactly_25_entries() {
        assert_eq!(
            PRIVESC_PATHS.len(),
            25,
            "PRIVESC_PATHS must have exactly 25 entries, found {}",
            PRIVESC_PATHS.len()
        );
    }
}
