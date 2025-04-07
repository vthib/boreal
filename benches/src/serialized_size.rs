use boreal_benches::{
    build_boreal_scanner, build_yara_rules, build_yara_x_rules, get_yara_files_from_path,
    RULES_SETS,
};

fn main() {
    for (name, rules_path) in &RULES_SETS {
        println!("{name}:");

        let rules = get_yara_files_from_path(rules_path);

        let boreal_scanner = build_boreal_scanner(&rules);
        let mut yara_rules = build_yara_rules(&rules);
        let yara_x_rules = build_yara_x_rules(&rules);

        let mut out = Vec::new();
        boreal_scanner.to_bytes(&mut out).unwrap();
        println!("boreal: {}", datasize(out.len()));

        let mut out = Vec::new();
        yara_rules.save_to_stream(&mut out).unwrap();
        println!("yara:   {}", datasize(out.len()));

        let out = yara_x_rules.serialize().unwrap();
        println!("yara-x: {}", datasize(out.len()));

        println!("");
    }
}

fn datasize(v: usize) -> String {
    if v > 1024 * 1024 {
        format!("{:.2}MB", (v as f64) / 1024. / 1024.)
    } else if v > 1024 {
        format!("{:.2}KB", (v as f64) / 1024.)
    } else {
        format!("{}B", v)
    }
}
