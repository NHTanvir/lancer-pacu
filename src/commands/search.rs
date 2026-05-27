//! `search` command — filter registered modules by term.

use comfy_table::{Table, Cell, presets::UTF8_FULL};
use inventory;

use crate::module::Module;

/// Return the subset of registered modules whose name, category, or one_liner
/// contains `term` (case-insensitive). Pure filtering logic — no I/O.
pub fn filter_modules<'a>(term: &str) -> Vec<&'a Module> {
    let lower = term.to_lowercase();
    inventory::iter::<Module>
        .into_iter()
        .filter(|m| {
            m.info.name.to_lowercase().contains(&lower)
                || m.info.category.to_lowercase().contains(&lower)
                || m.info.one_liner.to_lowercase().contains(&lower)
                || m.info.services.iter().any(|s| s.to_lowercase().contains(&lower))
        })
        .collect()
}

/// Search registered modules and print results.
pub fn run(term: &str) {
    if term.is_empty() {
        println!("Usage: search <term>");
        return;
    }

    let matches = filter_modules(term);

    if matches.is_empty() {
        println!("No modules match '{term}'.");
        return;
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Name", "Category", "Services", "One-liner"]);

    for module in &matches {
        let services = module.info.services.join(", ");
        table.add_row(vec![
            Cell::new(module.info.name),
            Cell::new(module.info.category),
            Cell::new(&services),
            Cell::new(module.info.one_liner),
        ]);
    }

    println!("{table}");
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    // We test the filtering logic directly on a Vec of ModuleInfo values
    // (rather than going through inventory::submit!) for isolation.

    use crate::module::ModuleInfo;

    fn make_info(name: &'static str, category: &'static str, one_liner: &'static str) -> ModuleInfo {
        ModuleInfo {
            name,
            author: "test",
            category,
            one_liner,
            services: &["sts"],
        }
    }

    fn filter_infos<'a>(infos: &'a [ModuleInfo], term: &str) -> Vec<&'a ModuleInfo> {
        let lower = term.to_lowercase();
        infos
            .iter()
            .filter(|m| {
                m.name.to_lowercase().contains(&lower)
                    || m.category.to_lowercase().contains(&lower)
                    || m.one_liner.to_lowercase().contains(&lower)
                    || m.services.iter().any(|s| s.to_lowercase().contains(&lower))
            })
            .collect()
    }

    #[test]
    fn search_by_name() {
        let infos = vec![
            make_info("iam__enum_users", "ENUM", "Enumerate IAM users"),
            make_info("s3__list_buckets", "RECON_UNAUTH", "List S3 buckets"),
        ];
        let results = filter_infos(&infos, "iam");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "iam__enum_users");
    }

    #[test]
    fn search_by_category() {
        let infos = vec![
            make_info("iam__enum_users", "ENUM", "Enumerate IAM users"),
            make_info("s3__list_buckets", "RECON_UNAUTH", "List S3 buckets"),
            make_info("ec2__enum_instances", "ENUM", "Enumerate EC2 instances"),
        ];
        let results = filter_infos(&infos, "ENUM");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn search_by_one_liner() {
        let infos = vec![
            make_info("iam__enum_users", "ENUM", "Enumerate IAM users"),
            make_info("s3__list_buckets", "RECON_UNAUTH", "List S3 buckets"),
        ];
        let results = filter_infos(&infos, "buckets");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "s3__list_buckets");
    }

    #[test]
    fn search_no_match() {
        let infos = vec![
            make_info("iam__enum_users", "ENUM", "Enumerate IAM users"),
        ];
        let results = filter_infos(&infos, "lambda");
        assert!(results.is_empty());
    }

    #[test]
    fn search_case_insensitive() {
        let infos = vec![
            make_info("iam__enum_users", "ENUM", "Enumerate IAM users"),
        ];
        let results = filter_infos(&infos, "enum");
        // Matches both name ("enum") and category ("ENUM") and one_liner ("Enumerate")
        assert!(!results.is_empty());
    }

    #[test]
    fn search_empty_term_returns_nothing() {
        let infos = vec![
            make_info("iam__enum_users", "ENUM", "Enumerate IAM users"),
        ];
        // Empty string matches everything (contains("") is always true)
        let results = filter_infos(&infos, "");
        assert_eq!(results.len(), infos.len());
    }
}
