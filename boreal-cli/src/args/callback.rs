use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};

use super::WarningMode;

#[derive(Clone, Debug)]
pub struct CallbackOptions {
    pub print_strings_matches_data: bool,
    pub print_string_length: bool,
    pub print_xor_key: bool,
    pub print_metadata: bool,
    pub print_namespace: bool,
    pub print_tags: bool,
    pub print_count: bool,
    pub print_statistics: bool,
    pub print_module_data: bool,
    pub count_limit: Option<u64>,
    pub identifier: Option<String>,
    pub tag: Option<String>,
    pub negate: bool,
    pub warning_mode: WarningMode,
}

impl CallbackOptions {
    pub fn from_args(args: &ArgMatches, warning_mode: WarningMode) -> Self {
        Self {
            print_strings_matches_data: args.get_flag("print_strings"),
            print_string_length: args.get_flag("print_string_length"),
            print_xor_key: args.get_flag("print_xor_key"),
            print_metadata: args.get_flag("print_metadata"),
            print_namespace: args.get_flag("print_namespace"),
            print_tags: args.get_flag("print_tags"),
            print_count: args.get_flag("count"),
            print_statistics: args.get_flag("print_scan_statistics"),
            print_module_data: args.get_flag("print_module_data"),
            count_limit: args.get_one::<u64>("count_limit").copied(),
            identifier: args.get_one("identifier").cloned(),
            tag: args.get_one("tag").cloned(),
            negate: args.get_flag("negate"),
            warning_mode,
        }
    }

    pub fn print_strings_matches(&self) -> bool {
        self.print_strings_matches_data || self.print_string_length || self.print_xor_key
    }
}

pub fn add_callback_args(command: Command) -> Command {
    command
        .next_help_heading("Display options")
        .arg(
            Arg::new("print_strings")
                .short('s')
                .long("print-strings")
                .action(ArgAction::SetTrue)
                .help("Print strings matches")
                .long_help(
                    "Print strings matches.\n\n\
                     Note that enabling this parameter will force the \
                     computation of all string matches,\ndisabling \
                     the no scan optimization in the process.",
                ),
        )
        .arg(
            Arg::new("print_string_length")
                .short('L')
                .long("print-string-length")
                .action(ArgAction::SetTrue)
                .help("Print the length of strings matches")
                .long_help(
                    "Print the length of strings matches.\n\n\
                     Note that enabling this parameter will force the \
                     computation of all string matches,\ndisabling \
                     the no scan optimization in the process.",
                ),
        )
        .arg(
            Arg::new("print_xor_key")
                .short('X')
                .long("print-xor-key")
                .action(ArgAction::SetTrue)
                .help("Print the xor key and the plaintext of matched strings")
                .long_help(
                    "Print the xor key and the plaintext of matched strings.\n\n\
                     Note that enabling this parameter will force the \
                     computation of all string matches,\ndisabling \
                     the no scan optimization in the process.",
                ),
        )
        .arg(
            Arg::new("print_metadata")
                .short('m')
                .long("print-meta")
                .action(ArgAction::SetTrue)
                .help("Print rule metadatas"),
        )
        .arg(
            Arg::new("print_namespace")
                .short('e')
                .long("print-namespace")
                .action(ArgAction::SetTrue)
                .help("Print rule namespace"),
        )
        .arg(
            Arg::new("print_tags")
                .short('g')
                .long("print-tags")
                .action(ArgAction::SetTrue)
                .help("Print rule tags"),
        )
        .arg(
            Arg::new("count")
                .short('c')
                .long("count")
                .action(ArgAction::SetTrue)
                .help("Print number of rules that matched (or did not match if negate is set)"),
        )
        .arg(
            Arg::new("print_scan_statistics")
                .long("scan-stats")
                .action(ArgAction::SetTrue)
                .help("Display statistics on rules' evaluation"),
        )
        .arg(
            Arg::new("print_module_data")
                .short('D')
                .long("print-module-data")
                .action(ArgAction::SetTrue)
                .help("Print module data"),
        )
        .arg(
            Arg::new("count_limit")
                .short('l')
                .long("max-rules")
                .value_name("NUMBER")
                .value_parser(value_parser!(u64))
                .help("Abort the scan once NUMBER rules have been matched (or not matched if negate is set)")
        )
        .arg(
            Arg::new("identifier")
                .short('i')
                .long("identifier")
                .value_name("IDENTIFIER")
                .value_parser(value_parser!(String))
                .help("Print only rules with the given name"),
        )
        .arg(
            Arg::new("tag")
                .short('t')
                .long("tag")
                .value_name("TAG")
                .value_parser(value_parser!(String))
                .help("Print only rules with the given tag"),
        )
        .arg(
            Arg::new("negate")
                .short('n')
                .long("negate")
                .action(ArgAction::SetTrue)
                .help("only print rules that *do not* match"),
        )
}
