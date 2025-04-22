//! Measure the compiled size of rules.
//!
//! This binary must be used with a profiler such as Massif:
//!
//! `valgrind --tool=massif ./compiled_size boreal-speed panopticon`
//!
//! Then use the last heap measurement to get the compiled size.
use boreal_benches::{
    build_boreal_scanner, build_yara_rules, build_yara_x_rules, get_yara_files_from_path,
    RULES_SETS,
};

fn main() {
    let mut args = std::env::args();
    let arg0 = args.next().unwrap();
    if args.len() != 2 {
        eprintln!(
            "usage: {} <engine> <rules_name>\n  \
            engine: boreal-speed | boreal-memory | yara | yara-x\n  \
            rules_name: orion | atr | ...",
            arg0
        );
        std::process::exit(1);
    }
    let engine = args.next().unwrap();
    let rules_name = args.next().unwrap();

    let Some(rules_path) = RULES_SETS
        .iter()
        .find(|(name, _)| name == &rules_name)
        .map(|(_, path)| path)
    else {
        eprintln!(
            "cannot find rules set {} in {:?}",
            rules_name,
            RULES_SETS.iter().map(|(name, _)| name).collect::<Vec<_>>()
        );
        return;
    };

    let rules = get_yara_files_from_path(rules_path);

    if engine == "boreal-speed" {
        let _boreal_scanner = build_boreal_scanner(&rules, true);
        std::process::exit(0);
    } else if engine == "boreal-memory" {
        let _boreal_scanner = build_boreal_scanner(&rules, false);
        std::process::exit(0);
    } else if engine == "yara" {
        let _yara_rules = build_yara_rules(&rules);
        std::process::exit(0);
    } else if engine == "yara-x" {
        let _yara_x_rules = build_yara_x_rules(&rules);
        std::process::exit(0);
    }
}
