use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};

#[derive(Debug)]
pub struct InputOptions {
    pub scan_list: bool,
    pub no_follow_symlinks: bool,
    pub recursive: bool,
    pub skip_larger: Option<u64>,
    pub input: String,
    pub no_mmap: bool,
    pub nb_threads: usize,
}

impl InputOptions {
    pub fn from_args(args: &mut ArgMatches, input: Option<String>) -> Self {
        let no_mmap = if cfg!(feature = "memmap") {
            args.get_flag("no_mmap")
        } else {
            false
        };
        let nb_threads = if let Some(nb) = args.get_one::<usize>("threads") {
            std::cmp::min(1, *nb)
        } else {
            std::thread::available_parallelism()
                .map(std::num::NonZero::get)
                .unwrap_or(32)
        };

        Self {
            scan_list: args.get_flag("scan_list"),
            no_follow_symlinks: args.get_flag("no_follow_symlinks"),
            recursive: args.get_flag("recursive"),
            skip_larger: args.remove_one::<u64>("skip_larger"),
            input: input.unwrap_or_else(|| args.remove_one("input").unwrap()),
            no_mmap,
            nb_threads,
        }
    }
}

pub fn add_input_args(command: Command, in_yr_subcommand: bool) -> Command {
    let mut command = command
        .next_help_heading("Input options")
        .arg(
            Arg::new("scan_list")
                .long("scan-list")
                .action(ArgAction::SetTrue)
                .help("Scan files listed in input, each line is a path to a file or directory"),
        )
        .arg(
            Arg::new("no_follow_symlinks")
                .short('N')
                .long("no-follow-symlinks")
                .action(ArgAction::SetTrue)
                .help("Do not follow symlinks when scanning"),
        )
        .arg(
            Arg::new("recursive")
                .short('r')
                .long("recursive")
                .action(ArgAction::SetTrue)
                .help("Recursively search directories"),
        )
        .arg(
            Arg::new("skip_larger")
                .short('z')
                .long("skip-larger")
                .value_name("MAX_SIZE")
                .value_parser(value_parser!(u64))
                .help("Skip files larger than the given size when scanning a directory"),
        )
        .arg(
            Arg::new("threads")
                .short('p')
                .long("threads")
                .value_name("NUMBER")
                .value_parser(value_parser!(usize))
                .help("Number of threads to use when scanning directories"),
        );

    if cfg!(feature = "memmap") {
        command = command.arg(
            Arg::new("no_mmap")
                .long("no-mmap")
                .action(ArgAction::SetTrue)
                .help("Disable the use of memory maps.")
                .long_help(
                    "Disable the use of memory maps.\n\n\
                    By default, memory maps are used to load files to scan.\n\
                    This can cause the program to abort unexpectedly \
                    if files are simultaneous truncated.",
                ),
        );
    }

    if !in_yr_subcommand {
        command = command.next_help_heading(None).arg(
            Arg::new("input")
                .value_name("FILE | DIRECTORY | PID | SCAN_LIST")
                .value_parser(value_parser!(String))
                .help("Target to scan")
                .long_help(
                    "Target to scan.\n\n\
This can be either:\n
  - A path to a file.
  - A path to a directory, in which files will be scanned.
  - The pid of the a process to scan.
  - A file containing a list of targets to scan, one per line, if --scan-list \
    is specified.",
                ),
        );
    }

    command
}
