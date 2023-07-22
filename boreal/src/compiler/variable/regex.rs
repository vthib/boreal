use boreal_parser::VariableModifiers;

use crate::regex::{regex_hir_to_string, Hir, Regex};

use super::analysis::analyze_hir;
use super::literals::LiteralsDetails;
use super::matcher;
use super::matcher::validator::{ForwardValidator, ReverseValidator};
use super::{only_literals, CompiledVariable, VariableCompilationError};

/// Build a matcher for the given regex and string modifiers.
///
/// This function returns two values:
/// - The regex expression to use to match on this variable
/// - An optional expr used to validate matches, only set in the specific case of a widen regex
///   containing word boundaries.
pub(super) fn compile_regex(
    hir: &Hir,
    dot_all: bool,
    modifiers: &VariableModifiers,
) -> Result<CompiledVariable, VariableCompilationError> {
    let analysis = analyze_hir(hir, dot_all);

    let non_wide_regex = if analysis.has_word_boundaries && modifiers.wide {
        let expr = regex_hir_to_string(hir);
        Some(compile_regex_expr(expr, modifiers.nocase, dot_all)?)
    } else {
        None
    };

    // Do not use an AC if anchors are present, it will be much efficient to just run
    // the regex directly.
    if analysis.has_start_or_end_line {
        return Ok(CompiledVariable {
            literals: Vec::new(),
            matcher_kind: raw_matcher(hir, modifiers, dot_all)?,
            non_wide_regex,
        });
    }

    if let Some(count) = analysis.nb_alt_literals {
        // The regex can be covered entirely by literals. This is optimal, so use this if possible.
        // TODO: handle more modifiers
        if count < 100 && !modifiers.nocase && !modifiers.wide {
            if let Some(literals) = only_literals::hir_to_only_literals(hir) {
                return Ok(CompiledVariable {
                    literals,
                    matcher_kind: matcher::MatcherKind::Literals,
                    non_wide_regex,
                });
            }
        }
    }

    let LiteralsDetails {
        mut literals,
        pre_hir,
        post_hir,
    } = super::literals::get_literals_details(hir);

    // If some literals are too small, don't use them, they would match too
    // many times.
    if literals.iter().any(|lit| lit.len() < 2) {
        literals.clear();
    }
    apply_ascii_wide_flags_on_literals(&mut literals, modifiers);

    let mut use_ac = !literals.is_empty();

    if let Some(pre) = &pre_hir {
        let left_analysis = analyze_hir(pre, dot_all);
        if left_analysis.has_greedy_repetitions {
            // Greedy repetitions on the left side of the literals is not for the moment handled.
            // This is because the repetition can "eat" the literals against which we matched,
            // meaning that the pre/post split is not valid.
            //
            // For example, a regex that looks like: `a.+foo.+b` will extract the literal foo,
            // but against the string `aafoobbaafoobb`, it will match on the entire string,
            // while we will match against both "foo" occurrences.
            use_ac = false;
        }
    }

    let matcher_kind = if use_ac {
        matcher::MatcherKind::Atomized {
            left_validator: match pre_hir {
                Some(hir) => Some(
                    ReverseValidator::new(&hir, modifiers, dot_all)
                        .map_err(VariableCompilationError::Regex)?,
                ),
                None => None,
            },
            right_validator: match post_hir {
                Some(hir) => Some(
                    ForwardValidator::new(&hir, modifiers, dot_all)
                        .map_err(VariableCompilationError::Regex)?,
                ),
                None => None,
            },
        }
    } else {
        raw_matcher(hir, modifiers, dot_all)?
    };

    Ok(CompiledVariable {
        literals,
        matcher_kind,
        non_wide_regex,
    })
}

fn raw_matcher(
    hir: &Hir,
    modifiers: &VariableModifiers,
    dot_all: bool,
) -> Result<matcher::MatcherKind, VariableCompilationError> {
    Ok(matcher::MatcherKind::Raw(
        matcher::raw::RawMatcher::new(hir, modifiers, dot_all)
            .map_err(VariableCompilationError::Regex)?,
    ))
}

fn apply_ascii_wide_flags_on_literals(literals: &mut Vec<Vec<u8>>, modifiers: &VariableModifiers) {
    if !modifiers.wide {
        return;
    }

    if modifiers.ascii {
        let wide_literals: Vec<_> = literals.iter().map(|v| widen_literal(v)).collect();
        literals.extend(wide_literals);
    } else {
        for lit in literals {
            *lit = widen_literal(lit);
        }
    }
}

fn widen_literal(literal: &[u8]) -> Vec<u8> {
    let mut new_lit = Vec::with_capacity(literal.len() * 2);
    for b in literal {
        new_lit.push(*b);
        new_lit.push(0);
    }
    new_lit
}

fn compile_regex_expr(
    expr: String,
    case_insensitive: bool,
    dot_all: bool,
) -> Result<Regex, VariableCompilationError> {
    Regex::from_string(expr, case_insensitive, dot_all).map_err(VariableCompilationError::Regex)
}
