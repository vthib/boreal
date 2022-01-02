//! Parsing methods for .yar files.
//!
//! This module mainly intends to match the lexical patterns used in libyara.
//!
//! All of the parsing functions, unless otherwise indicated, depends on the
//! following invariants:
//! - The received input has already been left-trimmed
//! - The returned input is right-trimmed
//! The [`nom_recipes::rtrim`] function is provided to make this easier.
//!
//! Progress:
//! [x] hex strings initial impl is complete, need integration testing.
//! [ ] re strings needs to be investigated.
//! [ ] yar files are in progress.
//!   lexer:
//!     [x] identifiers
//!     [x] strings
//!     [x] regexes
//!     [ ] includes
//!   parser:
//!     [ ] all

// use nom::{
//     branch::alt,
//     bytes::complete::tag,
//     character::complete::{alpha1, alphanumeric1, char, multispace0 as sp0, multispace1 as sp1},
//     combinator::{map, recognize},
//     multi::many0,
//     sequence::{delimited, pair, preceded},
//     IResult,
// };

mod hex_string;
mod nom_recipes;
mod number;
mod primary_expression;
mod string;

#[cfg(test)]
mod test_utils;

// #[derive(Debug, PartialEq)]
// pub struct Rule {
//     name: String,
//     condition: String,
// }
//
// fn identifier(input: &str) -> IResult<&str, &str> {
//     recognize(pair(
//         alt((alpha1, tag("_"))),
//         many0(alt((alphanumeric1, tag("_")))),
//     ))(input)
// }
//
// fn condition(input: &str) -> IResult<&str, &str> {
//     let condition = tag("condition:");
//
//     preceded(preceded(sp0, condition), preceded(sp0, identifier))(input)
// }
//
// pub fn rule(input: &str) -> IResult<&str, Rule> {
//     let rule = tag("rule");
//
//     map(
//         pair(
//             preceded(preceded(sp0, rule), preceded(sp1, identifier)),
//             delimited(
//                 preceded(sp0, char('{')),
//                 condition,
//                 preceded(sp0, char('}')),
//             ),
//         ),
//         |(name, condition)| Rule {
//             name: name.to_string(),
//             condition: condition.to_string(),
//         },
//     )(input)
// }
//
// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn parse_simple_rule() {
//         fn test_rule(rule_str: &str, expected_name: &str, expected_condition: &str) {
//             assert_eq!(
//                 rule(rule_str),
//                 Ok((
//                     "",
//                     Rule {
//                         name: expected_name.to_owned(),
//                         condition: expected_condition.to_owned(),
//                     }
//                 ))
//             );
//         }
//
//         test_rule("rule test { condition: true }", "test", "true");
//         test_rule("rule bar {condition:false }", "bar", "false");
//         test_rule("rule _ba9r_0{condition:false}", "_ba9r_0", "false");
//     }
// }
//
