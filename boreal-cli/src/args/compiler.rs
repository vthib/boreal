use boreal::compiler::{CompilerProfile, ExternalValue};
use clap::parser::Values;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};

#[derive(Debug)]
pub struct CompilerOptions {
    pub profile: Option<CompilerProfile>,
    pub compute_statistics: bool,
    pub max_strings_per_rule: Option<usize>,
    pub defines: Option<Values<(String, ExternalValue)>>,
}

impl CompilerOptions {
    pub fn from_args(args: &mut ArgMatches) -> Self {
        Self {
            profile: args.remove_one::<CompilerProfile>("profile"),
            compute_statistics: args.get_flag("string_statistics"),
            max_strings_per_rule: args.remove_one::<usize>("max_strings_per_rule"),
            defines: args.remove_many::<(String, ExternalValue)>("define"),
        }
    }
}

pub fn add_compiler_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("profile")
                .long("profile")
                .value_name("speed|memory")
                .value_parser(parse_compiler_profile)
                .help("Profile to use when compiling rules"),
        )
        .arg(
            Arg::new("string_statistics")
                .long("string-stats")
                .action(ArgAction::SetTrue)
                .help("Display statistics on rules' compilation"),
        )
        .arg(
            Arg::new("max_strings_per_rule")
                .long("max-strings-per-rule")
                .value_name("NUMBER")
                .value_parser(value_parser!(usize))
                .help("Maximum number of strings in a single rule"),
        )
        .arg(
            Arg::new("define")
                .short('d')
                .long("define")
                .value_name("VAR=VALUE")
                .action(ArgAction::Append)
                .value_parser(parse_define)
                .help("Define a symbol that can be used in rules"),
        )
}

fn parse_compiler_profile(profile: &str) -> Result<CompilerProfile, String> {
    match profile {
        "speed" => Ok(CompilerProfile::Speed),
        "memory" => Ok(CompilerProfile::Memory),
        _ => Err("invalid value".to_string()),
    }
}

fn parse_define(arg: &str) -> Result<(String, ExternalValue), String> {
    let Some((name, value)) = arg.split_once('=') else {
        return Err("missing '=' delimiter".to_owned());
    };

    let external_value = if value == "true" {
        ExternalValue::Boolean(true)
    } else if value == "false" {
        ExternalValue::Boolean(false)
    } else if value.contains('.') {
        match value.parse::<f64>() {
            Ok(v) => ExternalValue::Float(v),
            Err(_) => ExternalValue::Bytes(value.as_bytes().to_vec()),
        }
    } else {
        match value.parse::<i64>() {
            Ok(v) => ExternalValue::Integer(v),
            Err(_) => ExternalValue::Bytes(value.as_bytes().to_vec()),
        }
    };

    Ok((name.to_owned(), external_value))
}
