use boreal_parser::regex::{
    BracketedClass, BracketedClassItem, ClassKind, Node, RepetitionKind, RepetitionRange,
};
use boreal_parser::{HexMask, HexToken, VariableFlags};

use crate::regex::regex_ast_to_string;

use super::atomized_regex::AtomizedRegex;
use super::{LiteralsMatcher, Matcher, RegexMatcher, RegexType, VariableCompilationError};

mod literals;

pub(super) fn compile_hex_string(
    hex_string: Vec<HexToken>,
    flags: VariableFlags,
) -> Result<(Vec<Vec<u8>>, Box<dyn Matcher>), VariableCompilationError> {
    if literals::can_use_only_literals(&hex_string) {
        Ok((
            literals::hex_string_to_only_literals(hex_string),
            Box::new(LiteralsMatcher {}),
        ))
    } else {
        let ast = hex_string_to_ast(hex_string);

        let (literals, regex_type) = match super::atom::build_atomized_expressions(&ast) {
            Some(exprs) => (
                exprs.literals.clone(),
                RegexType::Atomized(AtomizedRegex::new(exprs, false, true)?),
            ),
            None => {
                let expr = regex_ast_to_string(&ast);
                (
                    Vec::new(),
                    RegexType::Raw(super::compile_regex_expr(&expr, false, true)?),
                )
            }
        };

        Ok((
            literals,
            Box::new(RegexMatcher {
                regex_type,
                flags,
                non_wide_regex: None,
            }),
        ))
    }
}

pub(super) fn hex_string_to_ast(hex_string: Vec<HexToken>) -> Node {
    Node::Concat(hex_string.into_iter().map(hex_token_to_ast).collect())
}

fn hex_token_to_ast(token: HexToken) -> Node {
    match token {
        HexToken::Byte(b) => Node::Literal(b),
        HexToken::MaskedByte(b, mask) => match mask {
            HexMask::Left => Node::Class(ClassKind::Bracketed(BracketedClass {
                items: (0..=0xF)
                    .map(|i| BracketedClassItem::Literal((i << 4) + b))
                    .collect(),
                negated: false,
            })),
            HexMask::Right => {
                let b = b << 4;
                Node::Class(ClassKind::Bracketed(BracketedClass {
                    items: vec![BracketedClassItem::Range(b, b + 0x0F)],
                    negated: false,
                }))
            }
            HexMask::All => Node::Dot,
        },
        HexToken::Jump(jump) => {
            let kind = match (jump.from, jump.to) {
                (from, None) => RepetitionKind::Range(RepetitionRange::AtLeast(from)),
                (from, Some(to)) => RepetitionKind::Range(RepetitionRange::Bounded(from, to)),
            };
            Node::Repetition {
                node: Box::new(Node::Dot),
                kind,
                greedy: false,
            }
        }
        HexToken::Alternatives(elems) => Node::Group(Box::new(Node::Alternation(
            elems.into_iter().map(hex_string_to_ast).collect(),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::parse_hex_string;
    use super::*;

    #[test]
    fn test_hex_string_to_regex() {
        #[track_caller]
        fn test(hex_string: &str, expected_regex: &str) {
            let hex_string = parse_hex_string(hex_string);

            let ast = hex_string_to_ast(hex_string);
            assert_eq!(&regex_ast_to_string(&ast), expected_regex);
        }

        test(
            "{ AB ?D 01 }",
            r"\xab[\x0d\x1d\x2d=M\x5dm\x7d\x8d\x9d\xad\xbd\xcd\xdd\xed\xfd]\x01",
        );
        test("{ C7 [-] ?? }", r"\xc7.{0,}?.");
        test(
            "{ C7 [3-] 5? 03 [-6] C7 ( FF 15 | E8 ) [4] 6A ( FF D? | E8 [2-4] ??) }",
            r"\xc7.{3,}?[P-_]\x03.{0,6}?\xc7(\xff\x15|\xe8).{4,4}?j(\xff[\xd0-\xdf]|\xe8.{2,4}?.)",
        );
    }
}
