//! `list` command — prints all registered modules in a table.

use comfy_table::{Table, Cell, presets::UTF8_FULL};
use inventory;

use crate::module::Module;

/// List all registered modules to stdout.
pub fn run() {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Name", "Category", "Services", "One-liner"]);

    let mut count = 0usize;
    for module in inventory::iter::<Module> {
        let services = module.info.services.join(", ");
        table.add_row(vec![
            Cell::new(module.info.name),
            Cell::new(module.info.category),
            Cell::new(&services),
            Cell::new(module.info.one_liner),
        ]);
        count += 1;
    }

    if count == 0 {
        println!("No modules registered yet.");
    } else {
        println!("{table}");
    }
}
