//! Detects rules that cannot match when none of their strings did.
//!
//! Most rules are of the form `<some checks> and <N> of ($a*)`, which is false as soon as
//! none of their strings matched, whatever the other checks evaluate to. Scanning a small
//! file spends most of its time walking the condition of every rule, so being able to
//! answer those without walking anything is worth the analysis.
use crate::compiler::expression::{Expression, ForSelection};

/// Can this condition be true even though none of the rule's strings matched?
///
/// Returns true only when the condition is guaranteed to evaluate to false in that case.
///
/// This algorithm is not complete and more of a best effort handling the very
/// common conditions. It may report false negatives but should never report
/// false positives.
pub(super) fn is_false_without_string_match(condition: &Expression) -> bool {
    eval(condition) == Value::False
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum Value {
    False,
    True,
    Unknown,
}

fn eval(expr: &Expression) -> Value {
    match expr {
        Expression::Boolean(b) => {
            if *b {
                Value::True
            } else {
                Value::False
            }
        }

        // A variable that did not match.
        Expression::Variable(_) | Expression::VariableAt { .. } | Expression::VariableIn { .. } => {
            Value::False
        }

        Expression::And(exprs) => {
            let mut res = Value::True;
            for e in exprs {
                match eval(e) {
                    Value::False => return Value::False,
                    Value::Unknown => res = Value::Unknown,
                    Value::True => (),
                }
            }
            res
        }
        Expression::Or(exprs) => {
            let mut res = Value::False;
            for e in exprs {
                match eval(e) {
                    Value::True => return Value::True,
                    Value::Unknown => res = Value::Unknown,
                    Value::False => (),
                }
            }
            res
        }
        Expression::Not(e) => match eval(e) {
            Value::False => Value::True,
            Value::True => Value::False,
            Value::Unknown => Value::Unknown,
        },

        // `for <selection> of <set>`. With no match the body is false for every variable of
        // the set, so only a selection that is satisfied by zero variables is true. The set is
        // never empty: the compiler rejects `them` without strings and a wildcard matching nothing.
        Expression::For(for_expr) => {
            // If the body does not evaluate to false, it cannot be resolved
            if eval(&for_expr.body) != Value::False {
                return Value::Unknown;
            }

            match &for_expr.selection {
                ForSelection::None => Value::True,
                ForSelection::Any | ForSelection::All => Value::False,
                ForSelection::Expr { expr, .. } => match &**expr {
                    Expression::Integer(n) => {
                        if *n > 0 {
                            Value::False
                        } else {
                            Value::True
                        }
                    }
                    _ => Value::Unknown,
                },
            }
        }

        // Everything else either depends on the scanned bytes, on a module, on another rule,
        // or is an arithmetic term, it is not handled here for now.
        Expression::Filesize
        | Expression::Entrypoint
        | Expression::ReadInteger { .. }
        | Expression::Integer(_)
        | Expression::Double(_)
        | Expression::Count(_)
        | Expression::CountInRange { .. }
        | Expression::Offset { .. }
        | Expression::Length { .. }
        | Expression::Neg(_)
        | Expression::Add(_, _)
        | Expression::Sub(_, _)
        | Expression::Mul(_, _)
        | Expression::Div(_, _)
        | Expression::Mod(_, _)
        | Expression::BitwiseXor(_, _)
        | Expression::BitwiseAnd(_, _)
        | Expression::BitwiseOr(_, _)
        | Expression::BitwiseNot(_)
        | Expression::ShiftLeft(_, _)
        | Expression::ShiftRight(_, _)
        | Expression::Cmp { .. }
        | Expression::Eq(_, _)
        | Expression::NotEq(_, _)
        | Expression::Contains { .. }
        | Expression::StartsWith { .. }
        | Expression::EndsWith { .. }
        | Expression::IEquals(_, _)
        | Expression::Matches(_, _)
        | Expression::Defined(_)
        | Expression::ForIdentifiers(_)
        | Expression::ForRules(_)
        | Expression::Module(_)
        | Expression::Rule(_)
        | Expression::ExternalSymbol(_)
        | Expression::Bytes(_)
        | Expression::Regex(_) => Value::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use crate::compiler::Compiler;

    /// Compile one rule, check the flag, and for a flagged rule check that it does not match
    /// a buffer holding none of its strings, which is what the flag asserts.
    #[track_caller]
    fn check(rule: &str, expected: bool) {
        let mut compiler = Compiler::new();
        let _r = compiler.add_rules_str(rule).unwrap();
        assert_eq!(
            compiler.rules[0].false_without_string_match, expected,
            "wrong flag for: {rule}"
        );
    }

    #[test]
    fn test_flagged() {
        check("rule a { strings: $a = \"xyzzy\" condition: $a }", true);
        check(
            "rule a { strings: $a = \"xyzzy\" condition: all of them }",
            true,
        );
        check(
            "rule a { strings: $a = \"xyzzy\" condition: any of them }",
            true,
        );
        check(
            "rule a { strings: $a = \"xyzzy\" condition: 2 of them }",
            true,
        );
        check(
            "rule a { strings: $a = \"xyzzy\" $b = \"plugh\" condition: 50% of them }",
            true,
        );
        check(
            "rule a { strings: $a = \"xyzzy\" condition: uint16(0) == 0x5a4d and $a }",
            true,
        );
        check(
            "rule a { strings: $a = \"xyzzy\" $b = \"plugh\" condition: ($a or $b) and filesize < 10MB }",
            true,
        );
        check(
            "rule a { strings: $a = \"xyzzy\" $c = \"canary\" condition: $a and not $c }",
            true,
        );
        check(
            "rule a { strings: $a = \"xyzzy\" condition: $a at 0 }",
            true,
        );
        check(
            "rule a { strings: $a = \"xyzzy\" condition: $a in (0..100) }",
            true,
        );
    }

    #[test]
    fn test_not_flagged() {
        check("rule a { condition: true }", false);
        check("rule a { condition: filesize > 0 }", false);
        check(
            "rule a { strings: $c = \"canary\" condition: uint16(0) == 0x5a4d and not $c }",
            false,
        );
        check(
            "rule a { strings: $a = \"xyzzy\" condition: not $a }",
            false,
        );
        check(
            "rule a { strings: $a = \"xyzzy\" condition: none of them }",
            false,
        );
        check(
            "rule a { strings: $a = \"xyzzy\" condition: 0 of them }",
            false,
        );
        check(
            "rule a { strings: $a = \"xyzzy\" condition: #a == 0 }",
            false,
        );
        check(
            "rule a { strings: $a = \"xyzzy\" condition: for all i in (1..#a) : ( @a[i] > 0 ) }",
            false,
        );
        check(
            "rule a { strings: $a = \"xyzzy\" condition: $a or filesize < 10MB }",
            false,
        );
    }
}
