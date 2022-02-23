use grep_regex::{RegexMatcher, RegexMatcherBuilder};

use boreal_parser::{Regex, VariableDeclaration, VariableDeclarationValue};

use super::CompilationError;

pub struct Variable {
    pub matcher: RegexMatcher,
}

pub(crate) fn compile_variable(decl: VariableDeclaration) -> Result<Variable, CompilationError> {
    // TODO: handle modifiers
    let mut matcher = RegexMatcherBuilder::new();
    let matcher = matcher.unicode(false).octal(false);

    let res = match decl.value {
        VariableDeclarationValue::String(s) => matcher.build_literals(&[s]),
        VariableDeclarationValue::Regex(Regex {
            expr,
            case_insensitive,
            dot_all,
        }) => matcher
            .case_insensitive(case_insensitive)
            .multi_line(dot_all)
            .dot_matches_new_line(dot_all)
            .build(&expr),
        VariableDeclarationValue::HexString(_) => todo!(),
    };

    Ok(Variable {
        matcher: res.map_err(|error| CompilationError::VariableCompilationError {
            variable_name: decl.name,
            error,
        })?,
    })
}
