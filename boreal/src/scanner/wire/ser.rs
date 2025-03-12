use std::collections::HashMap;

use boreal_parser::expression::ReadIntegerType;
use borsh::{io::Result, BorshSerialize};

use crate::compiler::expression::{
    Expression, ForIterator, ForSelection, RuleSet, VariableIndex, VariableSet,
};
use crate::compiler::module::{
    BoundedValueIndex, ModuleExpression, ModuleExpressionKind, ModuleOperations, ValueOperation,
};
use crate::compiler::variable::Variable;
use crate::compiler::ExternalValue;
use crate::matcher::{
    DfaValidator, HalfValidator, Matcher, MatcherKind, Modifiers, RawMatcher, SimpleNode,
    SimpleValidator, Validator,
};
use crate::module::Module;
use crate::regex::Regex;
use crate::scanner::{BytesPool, FragmentedScanMode, Inner, Rule, ScanParams, Scanner};
use crate::{BytesSymbol, Metadata, MetadataValue, StringSymbol};

use super::VERSION;

// TODO: check all usize serialization
// TODO: add limits for all arrays

pub fn serialize_scanner(scanner: &Scanner) -> Result<Vec<u8>> {
    let Scanner {
        inner,
        scan_params,
        external_symbols_values,
        module_user_data: _,
    } = scanner;
    let Inner {
        rules,
        global_rules,
        variables,
        ac_scan: _,
        modules,
        external_symbols_map,
        namespaces,
        bytes_pool,
    } = &**inner;

    let mut buf = Vec::new();

    serialize_header(&mut buf)?;
    serialize_scan_params(scan_params, &mut buf)?;
    serialize_external_symbols(external_symbols_values, external_symbols_map, &mut buf)?;
    serialize_namespaces(namespaces, &mut buf)?;
    serialize_bytes_pool(bytes_pool, &mut buf)?;
    serialize_variables(variables, &mut buf)?;
    serialize_modules(modules, &mut buf)?;
    serialize_rules(global_rules, &mut buf)?;
    serialize_rules(rules, &mut buf)?;

    Ok(buf)
}

fn serialize_header(buf: &mut Vec<u8>) -> Result<()> {
    "boreal_wire_".serialize(buf)?;
    VERSION.serialize(buf)?;
    // TODO: endianness check
    Ok(())
}

fn serialize_scan_params(scan_params: &ScanParams, buf: &mut Vec<u8>) -> Result<()> {
    let ScanParams {
        compute_full_matches,
        match_max_length,
        string_max_nb_matches,
        timeout_duration,
        compute_statistics,
        fragmented_scan_mode:
            FragmentedScanMode {
                modules_dynamic_values,
                can_refetch_regions,
            },
        process_memory,
        max_fetched_region_size,
        memory_chunk_size,
        callback_events,
        include_not_matched_rules,
    } = scan_params;

    compute_full_matches.serialize(buf)?;
    match_max_length.serialize(buf)?;
    string_max_nb_matches.serialize(buf)?;
    timeout_duration.map(|v| v.as_millis()).serialize(buf)?;
    compute_statistics.serialize(buf)?;
    modules_dynamic_values.serialize(buf)?;
    can_refetch_regions.serialize(buf)?;
    process_memory.serialize(buf)?;
    max_fetched_region_size.serialize(buf)?;
    memory_chunk_size.serialize(buf)?;
    callback_events.0.serialize(buf)?;
    include_not_matched_rules.serialize(buf)?;

    Ok(())
}

fn serialize_external_symbols(
    values: &[ExternalValue],
    indexes: &HashMap<String, usize>,
    buf: &mut Vec<u8>,
) -> Result<()> {
    (values.len() as u32).serialize(buf)?;
    for value in values {
        match value {
            ExternalValue::Integer(v) => {
                0_u8.serialize(buf)?;
                v.serialize(buf)?;
            }
            ExternalValue::Float(v) => {
                1_u8.serialize(buf)?;
                v.serialize(buf)?;
            }
            ExternalValue::Bytes(v) => {
                2_u8.serialize(buf)?;
                v.serialize(buf)?;
            }
            ExternalValue::Boolean(v) => {
                3_u8.serialize(buf)?;
                v.serialize(buf)?;
            }
        }
    }
    indexes.serialize(buf)?;

    Ok(())
}

fn serialize_namespaces(namespaces: &[Option<String>], buf: &mut Vec<u8>) -> Result<()> {
    namespaces.serialize(buf)?;
    Ok(())
}

fn serialize_bytes_pool(bytes_pool: &BytesPool, buf: &mut Vec<u8>) -> Result<()> {
    bytes_pool.buffer.serialize(buf)?;
    Ok(())
}

fn serialize_variables(variables: &[Variable], buf: &mut Vec<u8>) -> Result<()> {
    (variables.len() as u64).serialize(buf)?;
    for var in variables {
        let Variable {
            name,
            is_private,
            matcher:
                Matcher {
                    literals,
                    kind,
                    modifiers,
                },
        } = var;
        name.serialize(buf)?;
        is_private.serialize(buf)?;

        literals.serialize(buf)?;

        let Modifiers {
            fullword,
            wide,
            ascii,
            nocase,
            dot_all,
            xor_start,
        } = modifiers;
        fullword.serialize(buf)?;
        wide.serialize(buf)?;
        ascii.serialize(buf)?;
        nocase.serialize(buf)?;
        dot_all.serialize(buf)?;
        xor_start.serialize(buf)?;

        serialize_matcher_kind(kind, buf)?;
    }
    Ok(())
}

fn serialize_matcher_kind(kind: &MatcherKind, buf: &mut Vec<u8>) -> Result<()> {
    match kind {
        MatcherKind::Literals => {
            0_u8.serialize(buf)?;
        }
        MatcherKind::Atomized { validator } => {
            1_u8.serialize(buf)?;
            match validator {
                Validator::NonGreedy { forward, reverse } => {
                    0_u8.serialize(buf)?;
                    serialize_half_validator(forward.as_ref(), buf)?;
                    serialize_half_validator(reverse.as_ref(), buf)?;
                }
                Validator::Greedy { reverse, full } => {
                    1_u8.serialize(buf)?;
                    serialize_dfa_validator(reverse, buf)?;
                    serialize_dfa_validator(full, buf)?;
                }
            }
        }
        MatcherKind::Raw(RawMatcher {
            regex: _,
            exprs,
            non_wide_regex,
        }) => {
            2_u8.serialize(buf)?;
            exprs[0].serialize(buf)?;
            exprs[1].serialize(buf)?;
            non_wide_regex.as_ref().map(Regex::as_str).serialize(buf)?;
        }
    }

    Ok(())
}

fn serialize_simple_validator(simple: &SimpleValidator, buf: &mut Vec<u8>) -> Result<()> {
    let SimpleValidator { nodes, length } = simple;

    (nodes.len() as u64).serialize(buf)?;
    for node in nodes {
        match node {
            SimpleNode::Byte(b) => {
                0_u8.serialize(buf)?;
                b.serialize(buf)?;
            }
            SimpleNode::Mask { value, mask } => {
                1_u8.serialize(buf)?;
                value.serialize(buf)?;
                mask.serialize(buf)?;
            }
            SimpleNode::NegatedMask { value, mask } => {
                2_u8.serialize(buf)?;
                value.serialize(buf)?;
                mask.serialize(buf)?;
            }
            SimpleNode::Jump(v) => {
                3_u8.serialize(buf)?;
                v.serialize(buf)?;
            }
            SimpleNode::Dot => {
                4_u8.serialize(buf)?;
            }
        }
    }

    (*length as u64).serialize(buf)?;

    Ok(())
}

fn serialize_dfa_validator(dfa: &DfaValidator, buf: &mut Vec<u8>) -> Result<()> {
    let DfaValidator {
        dfa: _,
        pool: _,
        use_custom_wide_runner,
        exprs,
    } = dfa;

    exprs[0].serialize(buf)?;
    exprs[1].serialize(buf)?;
    use_custom_wide_runner.serialize(buf)?;

    Ok(())
}

fn serialize_half_validator(half: Option<&HalfValidator>, buf: &mut Vec<u8>) -> Result<()> {
    match half {
        None => {
            0_u8.serialize(buf)?;
        }
        Some(HalfValidator::Simple(simple)) => {
            1_u8.serialize(buf)?;
            serialize_simple_validator(simple, buf)?;
        }
        Some(HalfValidator::Dfa(dfa)) => {
            2_u8.serialize(buf)?;
            serialize_dfa_validator(dfa, buf)?;
        }
    }
    Ok(())
}

fn serialize_modules(modules: &[Box<dyn Module>], buf: &mut Vec<u8>) -> Result<()> {
    (modules.len() as u8).serialize(buf)?;
    for module in modules {
        module.get_name().serialize(buf)?;
    }
    Ok(())
}

fn serialize_rules(rules: &[Rule], buf: &mut Vec<u8>) -> Result<()> {
    (rules.len() as u64).serialize(buf)?;
    for rule in rules {
        let Rule {
            name,
            namespace_index,
            tags,
            metadatas,
            nb_variables,
            condition,
            is_private,
        } = rule;
        name.serialize(buf)?;
        namespace_index.serialize(buf)?;
        nb_variables.serialize(buf)?;
        is_private.serialize(buf)?;
        tags.serialize(buf)?;
        serialize_metadatas(metadatas, buf)?;
        serialize_expression(condition, buf)?;
    }
    Ok(())
}

fn serialize_metadatas(metadatas: &[Metadata], buf: &mut Vec<u8>) -> Result<()> {
    (metadatas.len() as u64).serialize(buf)?;
    for metadata in metadatas {
        let Metadata {
            name: StringSymbol { from, to },
            value,
        } = metadata;
        from.serialize(buf)?;
        to.serialize(buf)?;
        match value {
            MetadataValue::Bytes(BytesSymbol { from, to }) => {
                0_u8.serialize(buf)?;
                from.serialize(buf)?;
                to.serialize(buf)?;
            }
            MetadataValue::Integer(v) => {
                1_u8.serialize(buf)?;
                v.serialize(buf)?;
            }
            MetadataValue::Boolean(v) => {
                2_u8.serialize(buf)?;
                v.serialize(buf)?;
            }
        }
    }
    Ok(())
}

fn serialize_expression(expression: &Expression, buf: &mut Vec<u8>) -> Result<()> {
    match expression {
        Expression::Filesize => {
            0_u8.serialize(buf)?;
        }
        Expression::Entrypoint => {
            1_u8.serialize(buf)?;
        }
        Expression::ReadInteger { ty, addr } => {
            2_u8.serialize(buf)?;
            let v = match ty {
                ReadIntegerType::Int8 => 0_u8,
                ReadIntegerType::Uint8 => 1,
                ReadIntegerType::Int16 => 2,
                ReadIntegerType::Int16BE => 3,
                ReadIntegerType::Uint16 => 4,
                ReadIntegerType::Uint16BE => 5,
                ReadIntegerType::Int32 => 6,
                ReadIntegerType::Int32BE => 7,
                ReadIntegerType::Uint32 => 8,
                ReadIntegerType::Uint32BE => 9,
            };
            v.serialize(buf)?;
            serialize_expression(addr, buf)?;
        }
        Expression::Integer(v) => {
            3_u8.serialize(buf)?;
            v.serialize(buf)?;
        }
        Expression::Double(v) => {
            4_u8.serialize(buf)?;
            v.serialize(buf)?;
        }
        Expression::Count(variable_index) => {
            5_u8.serialize(buf)?;
            serialize_variable_index(variable_index, buf)?;
        }
        Expression::CountInRange {
            variable_index,
            from,
            to,
        } => {
            6_u8.serialize(buf)?;
            serialize_variable_index(variable_index, buf)?;
            serialize_expression(from, buf)?;
            serialize_expression(to, buf)?;
        }
        Expression::Offset {
            variable_index,
            occurence_number,
        } => {
            7_u8.serialize(buf)?;
            serialize_variable_index(variable_index, buf)?;
            serialize_expression(occurence_number, buf)?;
        }
        Expression::Length {
            variable_index,
            occurence_number,
        } => {
            8_u8.serialize(buf)?;
            serialize_variable_index(variable_index, buf)?;
            serialize_expression(occurence_number, buf)?;
        }
        Expression::Neg(expr) => {
            9_u8.serialize(buf)?;
            serialize_expression(expr, buf)?;
        }
        Expression::Add(a, b) => {
            10_u8.serialize(buf)?;
            serialize_expression(a, buf)?;
            serialize_expression(b, buf)?;
        }
        Expression::Sub(a, b) => {
            11_u8.serialize(buf)?;
            serialize_expression(a, buf)?;
            serialize_expression(b, buf)?;
        }
        Expression::Mul(a, b) => {
            12_u8.serialize(buf)?;
            serialize_expression(a, buf)?;
            serialize_expression(b, buf)?;
        }
        Expression::Div(a, b) => {
            13_u8.serialize(buf)?;
            serialize_expression(a, buf)?;
            serialize_expression(b, buf)?;
        }
        Expression::Mod(a, b) => {
            14_u8.serialize(buf)?;
            serialize_expression(a, buf)?;
            serialize_expression(b, buf)?;
        }
        Expression::BitwiseXor(a, b) => {
            15_u8.serialize(buf)?;
            serialize_expression(a, buf)?;
            serialize_expression(b, buf)?;
        }
        Expression::BitwiseAnd(a, b) => {
            16_u8.serialize(buf)?;
            serialize_expression(a, buf)?;
            serialize_expression(b, buf)?;
        }
        Expression::BitwiseOr(a, b) => {
            17_u8.serialize(buf)?;
            serialize_expression(a, buf)?;
            serialize_expression(b, buf)?;
        }
        Expression::BitwiseNot(v) => {
            18_u8.serialize(buf)?;
            serialize_expression(v, buf)?;
        }
        Expression::ShiftLeft(a, b) => {
            19_u8.serialize(buf)?;
            serialize_expression(a, buf)?;
            serialize_expression(b, buf)?;
        }
        Expression::ShiftRight(a, b) => {
            20_u8.serialize(buf)?;
            serialize_expression(a, buf)?;
            serialize_expression(b, buf)?;
        }
        Expression::And(exprs) => {
            21_u8.serialize(buf)?;
            (exprs.len() as u64).serialize(buf)?;
            for expr in exprs {
                serialize_expression(expr, buf)?;
            }
        }
        Expression::Or(exprs) => {
            22_u8.serialize(buf)?;
            (exprs.len() as u64).serialize(buf)?;
            for expr in exprs {
                serialize_expression(expr, buf)?;
            }
        }
        Expression::Not(v) => {
            23_u8.serialize(buf)?;
            serialize_expression(v, buf)?;
        }
        Expression::Cmp {
            left,
            right,
            less_than,
            can_be_equal,
        } => {
            24_u8.serialize(buf)?;
            serialize_expression(left, buf)?;
            serialize_expression(right, buf)?;
            less_than.serialize(buf)?;
            can_be_equal.serialize(buf)?;
        }
        Expression::Eq(a, b) => {
            25_u8.serialize(buf)?;
            serialize_expression(a, buf)?;
            serialize_expression(b, buf)?;
        }
        Expression::NotEq(a, b) => {
            26_u8.serialize(buf)?;
            serialize_expression(a, buf)?;
            serialize_expression(b, buf)?;
        }
        Expression::Contains {
            haystack,
            needle,
            case_insensitive,
        } => {
            27_u8.serialize(buf)?;
            serialize_expression(haystack, buf)?;
            serialize_expression(needle, buf)?;
            case_insensitive.serialize(buf)?;
        }
        Expression::StartsWith {
            expr,
            prefix,
            case_insensitive,
        } => {
            28_u8.serialize(buf)?;
            serialize_expression(expr, buf)?;
            serialize_expression(prefix, buf)?;
            case_insensitive.serialize(buf)?;
        }
        Expression::EndsWith {
            expr,
            suffix,
            case_insensitive,
        } => {
            29_u8.serialize(buf)?;
            serialize_expression(expr, buf)?;
            serialize_expression(suffix, buf)?;
            case_insensitive.serialize(buf)?;
        }
        Expression::IEquals(a, b) => {
            30_u8.serialize(buf)?;
            serialize_expression(a, buf)?;
            serialize_expression(b, buf)?;
        }
        Expression::Matches(expr, regex) => {
            31_u8.serialize(buf)?;
            serialize_expression(expr, buf)?;
            serialize_regex(regex, buf)?;
        }
        Expression::Defined(expr) => {
            32_u8.serialize(buf)?;
            serialize_expression(expr, buf)?;
        }
        Expression::Boolean(v) => {
            33_u8.serialize(buf)?;
            v.serialize(buf)?;
        }
        Expression::Variable(variable_index) => {
            34_u8.serialize(buf)?;
            variable_index.0.serialize(buf)?;
        }
        Expression::VariableAt {
            variable_index,
            offset,
        } => {
            35_u8.serialize(buf)?;
            variable_index.0.serialize(buf)?;
            serialize_expression(offset, buf)?;
        }
        Expression::VariableIn {
            variable_index,
            from,
            to,
        } => {
            36_u8.serialize(buf)?;
            variable_index.0.serialize(buf)?;
            serialize_expression(from, buf)?;
            serialize_expression(to, buf)?;
        }
        Expression::For {
            selection,
            set: VariableSet { elements },
            body,
        } => {
            37_u8.serialize(buf)?;
            serialize_for_selection(selection, buf)?;
            (elements.len() as u64).serialize(buf)?;
            for elem in elements {
                (*elem as u64).serialize(buf)?;
            }
            serialize_expression(body, buf)?;
        }
        Expression::ForIdentifiers {
            selection,
            iterator,
            body,
        } => {
            38_u8.serialize(buf)?;
            serialize_for_selection(selection, buf)?;
            match iterator {
                ForIterator::ModuleIterator(module_expr) => {
                    0_u8.serialize(buf)?;
                    serialize_module_expression(module_expr, buf)?;
                }
                ForIterator::Range { from, to } => {
                    1_u8.serialize(buf)?;
                    serialize_expression(from, buf)?;
                    serialize_expression(to, buf)?;
                }
                ForIterator::List(exprs) => {
                    2_u8.serialize(buf)?;
                    (exprs.len() as u64).serialize(buf)?;
                    for expr in exprs {
                        serialize_expression(expr, buf)?;
                    }
                }
            }
            serialize_expression(body, buf)?;
        }
        Expression::ForRules {
            selection,
            set: RuleSet {
                elements,
                already_matched,
            },
        } => {
            39_u8.serialize(buf)?;
            serialize_for_selection(selection, buf)?;
            (elements.len() as u64).serialize(buf)?;
            for elem in elements {
                (*elem as u64).serialize(buf)?;
            }
            (*already_matched as u64).serialize(buf)?;
        }
        Expression::Module(module_expr) => {
            40_u8.serialize(buf)?;
            serialize_module_expression(module_expr, buf)?;
        }
        Expression::Rule(v) => {
            41_u8.serialize(buf)?;
            (*v as u64).serialize(buf)?;
        }
        Expression::ExternalSymbol(v) => {
            42_u8.serialize(buf)?;
            (*v as u64).serialize(buf)?;
        }
        Expression::Bytes(BytesSymbol { from, to }) => {
            43_u8.serialize(buf)?;
            from.serialize(buf)?;
            to.serialize(buf)?;
        }
        Expression::Regex(regex) => {
            44_u8.serialize(buf)?;
            serialize_regex(regex, buf)?;
        }
    }

    Ok(())
}

fn serialize_variable_index(variable_index: &VariableIndex, buf: &mut Vec<u8>) -> Result<()> {
    variable_index.0.map(|v| v as u64).serialize(buf)?;
    Ok(())
}

fn serialize_for_selection(selection: &ForSelection, buf: &mut Vec<u8>) -> Result<()> {
    match selection {
        ForSelection::Any => 0_u8.serialize(buf)?,
        ForSelection::All => 1_u8.serialize(buf)?,
        ForSelection::None => 2_u8.serialize(buf)?,
        ForSelection::Expr { expr, as_percent } => {
            3_u8.serialize(buf)?;
            serialize_expression(expr, buf)?;
            as_percent.serialize(buf)?;
        }
    }
    Ok(())
}

fn serialize_module_expression(module_expr: &ModuleExpression, buf: &mut Vec<u8>) -> Result<()> {
    let ModuleExpression {
        kind,
        operations: ModuleOperations {
            expressions,
            operations,
        },
    } = module_expr;
    match kind {
        ModuleExpressionKind::BoundedModuleValueUse { index } => match index {
            BoundedValueIndex::Module(v) => {
                0_u8.serialize(buf)?;
                (*v as u64).serialize(buf)?;
            }
            BoundedValueIndex::BoundedStack(v) => {
                1_u8.serialize(buf)?;
                (*v as u64).serialize(buf)?;
            }
        },
        // TODO
        ModuleExpressionKind::StaticFunction { fun: _ } => {
            2_u8.serialize(buf)?;
        }
    }
    (expressions.len() as u64).serialize(buf)?;
    for expr in expressions {
        serialize_expression(expr, buf)?;
    }
    (operations.len() as u64).serialize(buf)?;
    for op in operations {
        match op {
            ValueOperation::Subfield(v) => {
                0_u8.serialize(buf)?;
                v.serialize(buf)?;
            }
            ValueOperation::Subscript => 1_u8.serialize(buf)?,
            ValueOperation::FunctionCall(v) => {
                2_u8.serialize(buf)?;
                (*v as u64).serialize(buf)?;
            }
        }
    }
    Ok(())
}

fn serialize_regex(regex: &Regex, buf: &mut Vec<u8>) -> Result<()> {
    // FIXME: add flags as well
    regex.as_str().serialize(buf)?;
    Ok(())
}
