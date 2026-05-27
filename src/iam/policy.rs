//! IAM policy document parsing and permission evaluation.
//!
//! Supports:
//!  - PolicyDocument / Statement deserialization
//!  - ActionField: single string or array of strings
//!  - ResourceField: wildcard, single string, or array
//!  - PolicyEvaluator: collects documents, evaluates effective Allow/Deny sets
//!  - URL-encoded policy documents (returned by GetUserPolicy / GetRolePolicy)

// ---------------------------------------------------------------------------
// Policy document types
// ---------------------------------------------------------------------------

/// A parsed IAM policy document.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyDocument {
    #[serde(rename = "Statement")]
    pub statements: Vec<Statement>,
}

/// A single statement within a policy document.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Statement {
    #[serde(rename = "Effect")]
    pub effect: String,
    #[serde(rename = "Action")]
    pub action: ActionField,
    #[serde(rename = "Resource", default)]
    pub resource: ResourceField,
}

/// `Action` can be a single string or an array of strings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ActionField {
    Single(String),
    Multiple(Vec<String>),
}

impl ActionField {
    /// Return all actions as a `Vec<String>`, normalized to lowercase.
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            ActionField::Single(s) => vec![s.to_lowercase()],
            ActionField::Multiple(v) => v.iter().map(|s| s.to_lowercase()).collect(),
        }
    }
}

/// `Resource` can be omitted (wildcard default), a single string, or an array.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
#[serde(untagged)]
pub enum ResourceField {
    #[default]
    Wildcard,
    Single(String),
    Multiple(Vec<String>),
}

// ---------------------------------------------------------------------------
// Effective permissions result
// ---------------------------------------------------------------------------

/// The resolved effective permissions for a principal across all policies.
///
/// Deny always overrides Allow (explicit deny wins).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EffectivePermissions {
    /// Actions explicitly allowed (after removing any explicitly denied).
    pub allow: Vec<String>,
    /// Actions explicitly denied.
    pub deny: Vec<String>,
}

// ---------------------------------------------------------------------------
// Policy evaluator
// ---------------------------------------------------------------------------

/// Accumulates multiple policy documents and evaluates effective permissions.
///
/// Deny always overrides Allow (explicit deny wins).
pub struct PolicyEvaluator {
    documents: Vec<PolicyDocument>,
}

impl PolicyEvaluator {
    /// Create a new empty evaluator.
    pub fn new() -> Self {
        PolicyEvaluator {
            documents: Vec::new(),
        }
    }

    /// Add a parsed policy document to the evaluator.
    pub fn add_document(&mut self, doc: PolicyDocument) {
        self.documents.push(doc);
    }

    /// Evaluate and return effective permissions across all added documents.
    ///
    /// Explicit deny wins: if an action appears in both Allow and Deny, it is
    /// included only in the `deny` set (removed from `allow`).
    pub fn evaluate(&self) -> EffectivePermissions {
        let mut allow: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut deny: std::collections::HashSet<String> = std::collections::HashSet::new();

        for doc in &self.documents {
            for stmt in &doc.statements {
                let actions = stmt.action.to_vec();
                match stmt.effect.as_str() {
                    "Allow" => {
                        for action in actions {
                            allow.insert(action);
                        }
                    }
                    "Deny" => {
                        for action in actions {
                            deny.insert(action);
                        }
                    }
                    // Ignore unknown effects.
                    _ => {}
                }
            }
        }

        // Explicit deny wins: remove denied actions from the allow set.
        let allow_filtered: Vec<String> = {
            let mut v: Vec<String> = allow.difference(&deny).cloned().collect();
            v.sort();
            v
        };

        let mut deny_vec: Vec<String> = deny.into_iter().collect();
        deny_vec.sort();

        EffectivePermissions {
            allow: allow_filtered,
            deny: deny_vec,
        }
    }
}

impl Default for PolicyEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Parse an IAM policy document JSON string, handling URL-encoding transparently.
///
/// IAM sometimes returns inline policy documents URL-encoded (e.g. from
/// `GetUserPolicy` / `GetRolePolicy`). This function decodes the string first
/// if it appears to be URL-encoded, then parses it as JSON.
pub fn parse_policy_document(raw: &str) -> anyhow::Result<PolicyDocument> {
    // Heuristic: URL-encoded JSON starts with '%7B' (= '{') or '%5B' (= '[')
    // or contains '%22' (= '"'). Attempt decode unconditionally; if the decoded
    // result is different, use it.
    let decoded = urlencoding::decode(raw)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| raw.to_owned());

    let json_str = if decoded != raw { &decoded } else { raw };

    serde_json::from_str::<PolicyDocument>(json_str)
        .map_err(|e| anyhow::anyhow!("failed to parse policy document: {e}\nJSON: {json_str}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ────────────────────────────────────────────────────────────

    fn make_doc(effect: &str, actions: ActionField) -> PolicyDocument {
        PolicyDocument {
            statements: vec![Statement {
                effect: effect.to_owned(),
                action: actions,
                resource: ResourceField::Single("*".to_owned()),
            }],
        }
    }

    // ── 1. Parse Action as single string ───────────────────────────────────

    #[test]
    fn parse_action_single_string() {
        let json = r#"{
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:ListUsers",
                "Resource": "*"
            }]
        }"#;
        let doc: PolicyDocument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.statements.len(), 1);
        let actions = doc.statements[0].action.to_vec();
        assert_eq!(actions, vec!["iam:listusers"]);
    }

    // ── 2. Parse Action as array ────────────────────────────────────────────

    #[test]
    fn parse_action_array() {
        let json = r#"{
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:CreatePolicyVersion", "iam:*"],
                "Resource": "*"
            }]
        }"#;
        let doc: PolicyDocument = serde_json::from_str(json).unwrap();
        let actions = doc.statements[0].action.to_vec();
        assert!(actions.contains(&"iam:createpolicyversion".to_owned()));
        assert!(actions.contains(&"iam:*".to_owned()));
    }

    // ── 3. Evaluator: two Allow documents merge their actions ───────────────

    #[test]
    fn evaluator_merges_allows() {
        let mut eval = PolicyEvaluator::new();
        eval.add_document(make_doc(
            "Allow",
            ActionField::Multiple(vec!["s3:getobject".to_owned(), "s3:putobject".to_owned()]),
        ));
        eval.add_document(make_doc(
            "Allow",
            ActionField::Single("iam:listusers".to_owned()),
        ));

        let perms = eval.evaluate();
        assert!(perms.allow.contains(&"s3:getobject".to_owned()));
        assert!(perms.allow.contains(&"s3:putobject".to_owned()));
        assert!(perms.allow.contains(&"iam:listusers".to_owned()));
        assert!(perms.deny.is_empty());
    }

    // ── 4. Evaluator: explicit Deny overrides Allow ─────────────────────────

    #[test]
    fn evaluator_deny_overrides_allow() {
        let mut eval = PolicyEvaluator::new();
        eval.add_document(make_doc(
            "Allow",
            ActionField::Multiple(vec![
                "iam:deletepolicy".to_owned(),
                "iam:listpolicies".to_owned(),
            ]),
        ));
        eval.add_document(make_doc(
            "Deny",
            ActionField::Single("iam:deletepolicy".to_owned()),
        ));

        let perms = eval.evaluate();
        // deletepolicy must be in deny and NOT in allow
        assert!(perms.deny.contains(&"iam:deletepolicy".to_owned()));
        assert!(!perms.allow.contains(&"iam:deletepolicy".to_owned()));
        // listpolicies is only allowed, so it stays in allow
        assert!(perms.allow.contains(&"iam:listpolicies".to_owned()));
    }

    // ── 5. Wildcard "iam:*" is stored as-is (no expansion) ──────────────────

    #[test]
    fn evaluator_wildcard_stored_as_is() {
        let mut eval = PolicyEvaluator::new();
        eval.add_document(make_doc(
            "Allow",
            ActionField::Single("iam:*".to_owned()),
        ));

        let perms = eval.evaluate();
        assert!(perms.allow.contains(&"iam:*".to_owned()),
            "wildcard action should be preserved as-is");
    }

    // ── 6. Parse URL-encoded policy document ────────────────────────────────

    #[test]
    fn parse_url_encoded_policy_document() {
        // Manually URL-encode the minimal policy JSON
        let plain = r#"{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
        let encoded = urlencoding::encode(plain).into_owned();

        let doc = parse_policy_document(&encoded).unwrap();
        assert_eq!(doc.statements.len(), 1);
        let actions = doc.statements[0].action.to_vec();
        assert_eq!(actions, vec!["s3:getobject"]);
    }

    // ── 7. Parse plain (non-encoded) policy document ─────────────────────────

    #[test]
    fn parse_plain_policy_document() {
        let plain = r#"{
            "Statement": [{
                "Effect": "Deny",
                "Action": ["iam:DeletePolicy", "iam:CreateUser"],
                "Resource": "*"
            }]
        }"#;
        let doc = parse_policy_document(plain).unwrap();
        let actions = doc.statements[0].action.to_vec();
        assert!(actions.contains(&"iam:deletepolicy".to_owned()));
        assert!(actions.contains(&"iam:createuser".to_owned()));
    }
}
