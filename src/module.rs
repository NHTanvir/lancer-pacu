//! Module trait, ModuleInfo struct, AwsContext, and module registry.

use std::pin::Pin;
use std::future::Future;

use aws_config::SdkConfig;
use aws_credential_types::Credentials;

/// Metadata attached to every module.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields used by future modules registered via inventory
pub struct ModuleInfo {
    pub name: &'static str,
    pub author: &'static str,
    /// One of: ENUM, ESCALATE, EXPLOIT, PERSIST, EVADE, EXFIL, LATERAL_MOVE, RECON_UNAUTH
    pub category: &'static str,
    pub one_liner: &'static str,
    pub services: &'static [&'static str],
}

/// Type alias for module run function signatures.
///
/// The `for<'ctx>` HRTB ensures the returned future captures the context
/// lifetime. Args slices are required to live at least as long as `'ctx`.
pub type ModuleRunFn = for<'ctx> fn(
    &'ctx AwsContext,
    &'ctx [&'ctx str],
) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'ctx>>;

/// A registered module: metadata + async run function.
pub struct Module {
    pub info: ModuleInfo,
    pub run: ModuleRunFn,
}

// Allow inventory to collect Module instances submitted from any module file.
inventory::collect!(Module);

/// AWS execution context passed to every module run function.
#[allow(dead_code)] // fields read by future modules at runtime
pub struct AwsContext {
    /// When true: log actions without executing write/mutate API calls.
    pub dry_run: bool,
    /// When true: state-mutating API calls are permitted.
    pub armed: bool,
    pub sdk_config: SdkConfig,
    /// SQLite session pool, present after DB initialisation.
    pub db_pool: Option<sqlx::SqlitePool>,
}

impl AwsContext {
    /// Create an AwsContext using the default AWS credential chain.
    pub fn new(dry_run: bool) -> Self {
        // We build the SdkConfig synchronously by blocking on the async load.
        // This is intentional at startup; the REPL runs in a tokio runtime.
        let sdk_config = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                aws_config::defaults(aws_config::BehaviorVersion::latest()).load().await
            })
        });
        AwsContext {
            dry_run,
            armed: !dry_run,
            sdk_config,
            db_pool: None,
        }
    }

    /// Create an AwsContext from explicit static credentials.
    pub async fn from_keys(
        ak: &str,
        sk: &str,
        token: Option<&str>,
        region: Option<&str>,
        dry_run: bool,
    ) -> Self {
        let creds = Credentials::new(
            ak,
            sk,
            token.map(|s| s.to_owned()),
            None,
            "lancer-pacu-static",
        );

        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .credentials_provider(creds);
        if let Some(r) = region {
            loader = loader.region(aws_config::meta::region::RegionProviderChain::first_try(
                aws_sdk_sts::config::Region::new(r.to_owned()),
            ));
        }
        let sdk_config = loader.load().await;

        AwsContext {
            dry_run,
            armed: !dry_run,
            sdk_config,
            db_pool: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that a Module can be constructed with the expected signature
    /// and that ModuleInfo fields are accessible.
    #[test]
    fn module_info_fields_accessible() {
        fn dummy_run(
            _ctx: &AwsContext,
            _args: &[&str],
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> {
            Box::pin(async { Ok(()) })
        }

        let m = Module {
            info: ModuleInfo {
                name: "test__dummy",
                author: "tester",
                category: "ENUM",
                one_liner: "A dummy test module",
                services: &["sts"],
            },
            run: dummy_run,
        };

        assert_eq!(m.info.name, "test__dummy");
        assert_eq!(m.info.category, "ENUM");
        assert_eq!(m.info.services, &["sts"]);
    }

    /// Verify the inventory is iterable without panicking.
    #[test]
    fn inventory_iter_does_not_panic() {
        let count = inventory::iter::<Module>.into_iter().count();
        // Week 3+: at least 3 modules registered.
        assert!(count >= 3, "expected at least 3 modules in inventory, got {count}");
    }
}
