use std::collections::HashMap;
use std::io::{Cursor, Result};
use std::sync::Arc;
use std::time::Duration;

use boreal_parser::expression::ReadIntegerType;
use borsh::BorshDeserialize as BD;

use crate::compiler::expression::{
    Expression, ForIterator, ForSelection, RuleSet, VariableIndex, VariableSet,
};
use crate::compiler::module::{
    BoundedValueIndex, ModuleExpression, ModuleExpressionKind, ModuleOperations, ValueOperation,
};
use crate::compiler::variable::Variable;
use crate::compiler::{CompilerProfile, ExternalValue};
use crate::matcher::{
    DfaValidator, HalfValidator, Matcher, MatcherKind, Modifiers, RawMatcher, SimpleNode,
    SimpleValidator, Validator,
};
use crate::module::{Module, ModuleUserData};
use crate::regex::Regex;
use crate::scanner::ac_scan::AcScan;
use crate::scanner::{
    BytesPool, CallbackEvents, FragmentedScanMode, Inner, Rule, ScanParams, Scanner,
};
use crate::{BytesSymbol, Metadata, MetadataValue, StringSymbol};

use super::VERSION;

// TODO: check all usize serialization
// TODO: add limits for all arrays

pub fn deserialize_scanner(
    bytes: &[u8],
    available_modules: &mut HashMap<&str, Box<dyn Module>>,
) -> Result<Scanner> {
    let mut cursor = Cursor::new(bytes);

    deserialize_reader(&mut cursor)?;
    let scan_params = deserialize_scan_params(&mut cursor)?;
    let (external_symbols_values, external_symbols_map) =
        deserialize_external_symbols(&mut cursor)?;
    let namespaces = deserialize_namespaces(&mut cursor)?;
    let bytes_pool = deserialize_bytes_pool(&mut cursor)?;
    let variables = deserialize_variables(&mut cursor)?;
    let modules = deserialize_modules(&mut cursor, available_modules)?;
    let global_rules = deserialize_rules(&mut cursor)?;
    let rules = deserialize_rules(&mut cursor)?;

    // TODO: profile
    let ac_scan = AcScan::new(&variables, CompilerProfile::Speed);

    let inner = Arc::new(Inner {
        rules,
        global_rules,
        variables,
        ac_scan,
        modules,
        external_symbols_map,
        namespaces,
        bytes_pool,
    });
    Ok(Scanner {
        inner,
        scan_params,
        external_symbols_values,
        module_user_data: ModuleUserData::default(),
    })
}

fn deserialize_reader(cursor: &mut Cursor<&[u8]>) -> Result<()> {
    let s: String = BD::deserialize_reader(cursor)?;
    assert_eq!(s, "boreal_wire_");
    let v: u32 = BD::deserialize_reader(cursor)?;
    assert_eq!(v, VERSION);
    // TODO: endianness check
    Ok(())
}

fn deserialize_scan_params(cursor: &mut Cursor<&[u8]>) -> Result<ScanParams> {
    let compute_full_matches = BD::deserialize_reader(cursor)?;
    let match_max_length = BD::deserialize_reader(cursor)?;
    let string_max_nb_matches = BD::deserialize_reader(cursor)?;
    let timeout_duration: Option<u64> = BD::deserialize_reader(cursor)?;
    let compute_statistics = BD::deserialize_reader(cursor)?;
    let modules_dynamic_values = BD::deserialize_reader(cursor)?;
    let can_refetch_regions = BD::deserialize_reader(cursor)?;
    let process_memory = BD::deserialize_reader(cursor)?;
    let max_fetched_region_size = BD::deserialize_reader(cursor)?;
    let memory_chunk_size = BD::deserialize_reader(cursor)?;
    let callback_events = BD::deserialize_reader(cursor)?;
    let include_not_matched_rules = BD::deserialize_reader(cursor)?;

    Ok(ScanParams {
        compute_full_matches,
        match_max_length,
        string_max_nb_matches,
        timeout_duration: timeout_duration.map(Duration::from_millis),
        compute_statistics,
        fragmented_scan_mode: FragmentedScanMode {
            modules_dynamic_values,
            can_refetch_regions,
        },
        process_memory,
        max_fetched_region_size,
        memory_chunk_size,
        callback_events: CallbackEvents(callback_events),
        include_not_matched_rules,
    })
}

fn deserialize_external_symbols(
    cursor: &mut Cursor<&[u8]>,
) -> Result<(Vec<ExternalValue>, HashMap<String, usize>)> {
    let values_len: u32 = BD::deserialize_reader(cursor)?;
    let mut values = Vec::with_capacity(values_len as usize);
    for _ in 0..values_len {
        let discriminant: u8 = BD::deserialize_reader(cursor)?;
        values.push(match discriminant {
            0 => {
                let v: i64 = BD::deserialize_reader(cursor)?;
                ExternalValue::Integer(v)
            }
            1 => {
                let v: f64 = BD::deserialize_reader(cursor)?;
                ExternalValue::Float(v)
            }
            2 => {
                let v: Vec<u8> = BD::deserialize_reader(cursor)?;
                ExternalValue::Bytes(v)
            }
            3 => {
                let v: bool = BD::deserialize_reader(cursor)?;
                ExternalValue::Boolean(v)
            }
            _ => todo!(),
        });
    }
    // FIXME: this uses usize
    let indexes: HashMap<String, usize> = BD::deserialize_reader(cursor)?;

    Ok((values, indexes))
}

fn deserialize_namespaces(cursor: &mut Cursor<&[u8]>) -> Result<Vec<Option<String>>> {
    BD::deserialize_reader(cursor)
}

fn deserialize_bytes_pool(cursor: &mut Cursor<&[u8]>) -> Result<BytesPool> {
    let buffer = BD::deserialize_reader(cursor)?;
    Ok(BytesPool { buffer })
}

fn deserialize_variables(cursor: &mut Cursor<&[u8]>) -> Result<Vec<Variable>> {
    let variables_len: u64 = BD::deserialize_reader(cursor)?;
    let mut variables = Vec::with_capacity(variables_len as usize);
    for _ in 0..variables_len {
        let name = BD::deserialize_reader(cursor)?;
        let is_private = BD::deserialize_reader(cursor)?;

        let literals = BD::deserialize_reader(cursor)?;

        let fullword = BD::deserialize_reader(cursor)?;
        let wide = BD::deserialize_reader(cursor)?;
        let ascii = BD::deserialize_reader(cursor)?;
        let nocase = BD::deserialize_reader(cursor)?;
        let dot_all = BD::deserialize_reader(cursor)?;
        let xor_start = BD::deserialize_reader(cursor)?;
        let modifiers = Modifiers {
            fullword,
            wide,
            ascii,
            nocase,
            dot_all,
            xor_start,
        };

        let kind = deserialize_matcher_kind(modifiers, cursor)?;

        variables.push(Variable {
            name,
            is_private,
            matcher: Matcher {
                literals,
                kind,
                modifiers,
            },
        });
    }

    Ok(variables)
}

fn deserialize_matcher_kind(
    modifiers: Modifiers,
    cursor: &mut Cursor<&[u8]>,
) -> Result<MatcherKind> {
    let discriminant: u8 = BD::deserialize_reader(cursor)?;
    Ok(match discriminant {
        0 => MatcherKind::Literals,
        1 => {
            let discriminant_validator: u8 = BD::deserialize_reader(cursor)?;
            let validator = match discriminant_validator {
                0 => {
                    let forward = deserialize_half_validator(modifiers, false, cursor)?;
                    let reverse = deserialize_half_validator(modifiers, true, cursor)?;
                    Validator::NonGreedy { forward, reverse }
                }
                1 => {
                    let reverse = deserialize_dfa_validator(modifiers, true, cursor)?;
                    let full = deserialize_dfa_validator(modifiers, false, cursor)?;
                    Validator::Greedy { reverse, full }
                }
                _ => todo!(),
            };
            MatcherKind::Atomized { validator }
        }
        2 => {
            let expr1: String = BD::deserialize_reader(cursor)?;
            let expr2: String = BD::deserialize_reader(cursor)?;
            let non_wide_regex: Option<String> = BD::deserialize_reader(cursor)?;
            // FIXME: params + unwrap
            let non_wide_regex =
                non_wide_regex.map(|expr| Regex::from_string(expr, false, false).unwrap());

            let builder = Regex::builder(modifiers.nocase, modifiers.dot_all);
            let regex = if expr2.is_empty() {
                builder.build_many(&[&expr1])
            } else {
                builder.build_many(&[&expr1, &expr2])
            };
            MatcherKind::Raw(RawMatcher {
                regex: regex.unwrap(),
                exprs: [expr1, expr2],
                non_wide_regex,
            })
        }
        _ => todo!(),
    })
}

fn deserialize_simple_validator(cursor: &mut Cursor<&[u8]>) -> Result<SimpleValidator> {
    let nodes_len: u64 = BD::deserialize_reader(cursor)?;
    let mut nodes = Vec::with_capacity(nodes_len as usize);
    for _ in 0..nodes_len {
        let discriminant: u8 = BD::deserialize_reader(cursor)?;
        nodes.push(match discriminant {
            0 => SimpleNode::Byte(BD::deserialize_reader(cursor)?),
            1 => {
                let value = BD::deserialize_reader(cursor)?;
                let mask = BD::deserialize_reader(cursor)?;
                SimpleNode::Mask { value, mask }
            }
            2 => {
                let value = BD::deserialize_reader(cursor)?;
                let mask = BD::deserialize_reader(cursor)?;
                SimpleNode::NegatedMask { value, mask }
            }
            3 => SimpleNode::Jump(BD::deserialize_reader(cursor)?),
            4 => SimpleNode::Dot,
            _ => todo!(),
        });
    }

    let length: u64 = BD::deserialize_reader(cursor)?;

    Ok(SimpleValidator {
        nodes,
        length: length as usize,
    })
}

fn deserialize_dfa_validator(
    modifiers: Modifiers,
    reverse: bool,
    cursor: &mut Cursor<&[u8]>,
) -> Result<DfaValidator> {
    let exprs = [
        BD::deserialize_reader(cursor)?,
        BD::deserialize_reader(cursor)?,
    ];
    let use_custom_wide_runner = BD::deserialize_reader(cursor)?;

    Ok(DfaValidator::build_from_exprs(exprs, modifiers, reverse, use_custom_wide_runner).unwrap())
}

fn deserialize_half_validator(
    modifiers: Modifiers,
    reverse: bool,
    cursor: &mut Cursor<&[u8]>,
) -> Result<Option<HalfValidator>> {
    let discriminant: u8 = BD::deserialize_reader(cursor)?;
    Ok(match discriminant {
        0 => None,
        1 => {
            let simple = deserialize_simple_validator(cursor)?;
            Some(HalfValidator::Simple(simple))
        }
        2 => {
            let dfa = deserialize_dfa_validator(modifiers, reverse, cursor)?;
            Some(HalfValidator::Dfa(dfa))
        }
        _ => todo!(),
    })
}

fn deserialize_modules(
    cursor: &mut Cursor<&[u8]>,
    available_modules: &mut HashMap<&str, Box<dyn Module>>,
) -> Result<Vec<Box<dyn Module>>> {
    let modules_len: u8 = BD::deserialize_reader(cursor)?;
    let mut modules = Vec::with_capacity(modules_len as usize);
    for _ in 0..modules_len {
        let name: String = BD::deserialize_reader(cursor)?;
        // FIXME unwrap
        modules.push(available_modules.remove(&*name).unwrap())
    }
    Ok(modules)
}

fn deserialize_rules(cursor: &mut Cursor<&[u8]>) -> Result<Vec<Rule>> {
    let rules_len: u64 = BD::deserialize_reader(cursor)?;
    let mut rules = Vec::with_capacity(rules_len as usize);
    for _ in 0..rules_len {
        let name = BD::deserialize_reader(cursor)?;
        let namespace_index = BD::deserialize_reader(cursor)?;
        let nb_variables = BD::deserialize_reader(cursor)?;
        let is_private = BD::deserialize_reader(cursor)?;
        let tags = BD::deserialize_reader(cursor)?;
        let metadatas = deserialize_metadatas(cursor)?;
        let condition = deserialize_expression(cursor)?;
        rules.push(Rule {
            name,
            namespace_index,
            tags,
            metadatas,
            nb_variables,
            condition,
            is_private,
        });
    }
    Ok(rules)
}

fn deserialize_metadatas(cursor: &mut Cursor<&[u8]>) -> Result<Vec<Metadata>> {
    let metadatas_len: u64 = BD::deserialize_reader(cursor)?;
    let mut metadatas = Vec::with_capacity(metadatas_len as usize);
    for _ in 0..metadatas_len {
        let from = BD::deserialize_reader(cursor)?;
        let to = BD::deserialize_reader(cursor)?;
        let discriminant: u8 = BD::deserialize_reader(cursor)?;
        let value = match discriminant {
            0 => {
                let from = BD::deserialize_reader(cursor)?;
                let to = BD::deserialize_reader(cursor)?;
                MetadataValue::Bytes(BytesSymbol { from, to })
            }
            1 => MetadataValue::Integer(BD::deserialize_reader(cursor)?),
            2 => MetadataValue::Boolean(BD::deserialize_reader(cursor)?),
            _ => todo!(),
        };
        metadatas.push(Metadata {
            name: StringSymbol { from, to },
            value,
        });
    }
    Ok(metadatas)
}

fn deserialize_expression(cursor: &mut Cursor<&[u8]>) -> Result<Expression> {
    let discriminant: u8 = BD::deserialize_reader(cursor)?;
    Ok(match discriminant {
        0 => Expression::Filesize,
        1 => Expression::Entrypoint,
        2 => {
            let discriminant: u8 = BD::deserialize_reader(cursor)?;
            let ty = match discriminant {
                0 => ReadIntegerType::Int8,
                1 => ReadIntegerType::Uint8,
                2 => ReadIntegerType::Int16,
                3 => ReadIntegerType::Int16BE,
                4 => ReadIntegerType::Uint16,
                5 => ReadIntegerType::Uint16BE,
                6 => ReadIntegerType::Int32,
                7 => ReadIntegerType::Int32BE,
                8 => ReadIntegerType::Uint32,
                9 => ReadIntegerType::Uint32BE,
                _ => todo!(),
            };
            let addr = deserialize_expression(cursor)?;
            Expression::ReadInteger {
                ty,
                addr: Box::new(addr),
            }
        }
        3 => Expression::Integer(BD::deserialize_reader(cursor)?),
        4 => Expression::Double(BD::deserialize_reader(cursor)?),
        5 => {
            let variable_index = deserialize_variable_index(cursor)?;
            Expression::Count(variable_index)
        }
        6 => {
            let variable_index = deserialize_variable_index(cursor)?;
            let from = Box::new(deserialize_expression(cursor)?);
            let to = Box::new(deserialize_expression(cursor)?);
            Expression::CountInRange {
                variable_index,
                from,
                to,
            }
        }
        7 => {
            let variable_index = deserialize_variable_index(cursor)?;
            let occurence_number = Box::new(deserialize_expression(cursor)?);
            Expression::Offset {
                variable_index,
                occurence_number,
            }
        }
        8 => {
            let variable_index = deserialize_variable_index(cursor)?;
            let occurence_number = Box::new(deserialize_expression(cursor)?);
            Expression::Length {
                variable_index,
                occurence_number,
            }
        }
        9 => {
            let expr = Box::new(deserialize_expression(cursor)?);
            Expression::Neg(expr)
        }
        10 => {
            let a = Box::new(deserialize_expression(cursor)?);
            let b = Box::new(deserialize_expression(cursor)?);
            Expression::Add(a, b)
        }
        11 => {
            let a = Box::new(deserialize_expression(cursor)?);
            let b = Box::new(deserialize_expression(cursor)?);
            Expression::Sub(a, b)
        }
        12 => {
            let a = Box::new(deserialize_expression(cursor)?);
            let b = Box::new(deserialize_expression(cursor)?);
            Expression::Mul(a, b)
        }
        13 => {
            let a = Box::new(deserialize_expression(cursor)?);
            let b = Box::new(deserialize_expression(cursor)?);
            Expression::Div(a, b)
        }
        14 => {
            let a = Box::new(deserialize_expression(cursor)?);
            let b = Box::new(deserialize_expression(cursor)?);
            Expression::Mod(a, b)
        }
        15 => {
            let a = Box::new(deserialize_expression(cursor)?);
            let b = Box::new(deserialize_expression(cursor)?);
            Expression::BitwiseXor(a, b)
        }
        16 => {
            let a = Box::new(deserialize_expression(cursor)?);
            let b = Box::new(deserialize_expression(cursor)?);
            Expression::BitwiseAnd(a, b)
        }
        17 => {
            let a = Box::new(deserialize_expression(cursor)?);
            let b = Box::new(deserialize_expression(cursor)?);
            Expression::BitwiseOr(a, b)
        }
        18 => {
            let a = Box::new(deserialize_expression(cursor)?);
            Expression::BitwiseNot(a)
        }
        19 => {
            let a = Box::new(deserialize_expression(cursor)?);
            let b = Box::new(deserialize_expression(cursor)?);
            Expression::ShiftLeft(a, b)
        }
        20 => {
            let a = Box::new(deserialize_expression(cursor)?);
            let b = Box::new(deserialize_expression(cursor)?);
            Expression::ShiftRight(a, b)
        }
        21 => {
            let exprs_len: u64 = BD::deserialize_reader(cursor)?;
            let mut exprs = Vec::with_capacity(exprs_len as usize);
            for _ in 0..exprs_len {
                exprs.push(deserialize_expression(cursor)?);
            }
            Expression::And(exprs)
        }
        22 => {
            let exprs_len: u64 = BD::deserialize_reader(cursor)?;
            let mut exprs = Vec::with_capacity(exprs_len as usize);
            for _ in 0..exprs_len {
                exprs.push(deserialize_expression(cursor)?);
            }
            Expression::Or(exprs)
        }
        23 => {
            let a = Box::new(deserialize_expression(cursor)?);
            Expression::Not(a)
        }
        24 => {
            let left = Box::new(deserialize_expression(cursor)?);
            let right = Box::new(deserialize_expression(cursor)?);
            let less_than = BD::deserialize_reader(cursor)?;
            let can_be_equal = BD::deserialize_reader(cursor)?;
            Expression::Cmp {
                left,
                right,
                less_than,
                can_be_equal,
            }
        }
        25 => {
            let a = Box::new(deserialize_expression(cursor)?);
            let b = Box::new(deserialize_expression(cursor)?);
            Expression::Eq(a, b)
        }
        26 => {
            let a = Box::new(deserialize_expression(cursor)?);
            let b = Box::new(deserialize_expression(cursor)?);
            Expression::NotEq(a, b)
        }
        27 => {
            let haystack = Box::new(deserialize_expression(cursor)?);
            let needle = Box::new(deserialize_expression(cursor)?);
            let case_insensitive = BD::deserialize_reader(cursor)?;
            Expression::Contains {
                haystack,
                needle,
                case_insensitive,
            }
        }
        28 => {
            let expr = Box::new(deserialize_expression(cursor)?);
            let prefix = Box::new(deserialize_expression(cursor)?);
            let case_insensitive = BD::deserialize_reader(cursor)?;
            Expression::StartsWith {
                expr,
                prefix,
                case_insensitive,
            }
        }
        29 => {
            let expr = Box::new(deserialize_expression(cursor)?);
            let suffix = Box::new(deserialize_expression(cursor)?);
            let case_insensitive = BD::deserialize_reader(cursor)?;
            Expression::EndsWith {
                expr,
                suffix,
                case_insensitive,
            }
        }
        30 => {
            let a = Box::new(deserialize_expression(cursor)?);
            let b = Box::new(deserialize_expression(cursor)?);
            Expression::IEquals(a, b)
        }
        31 => {
            let expr = Box::new(deserialize_expression(cursor)?);
            let regex = deserialize_regex(cursor)?;
            Expression::Matches(expr, regex)
        }
        32 => {
            let expr = Box::new(deserialize_expression(cursor)?);
            Expression::Defined(expr)
        }
        33 => Expression::Boolean(BD::deserialize_reader(cursor)?),
        34 => {
            let variable_index = deserialize_variable_index(cursor)?;
            Expression::Variable(variable_index)
        }
        35 => {
            let variable_index = deserialize_variable_index(cursor)?;
            let offset = Box::new(deserialize_expression(cursor)?);
            Expression::VariableAt {
                variable_index,
                offset,
            }
        }
        36 => {
            let variable_index = deserialize_variable_index(cursor)?;
            let from = Box::new(deserialize_expression(cursor)?);
            let to = Box::new(deserialize_expression(cursor)?);
            Expression::VariableIn {
                variable_index,
                from,
                to,
            }
        }
        37 => {
            let selection = deserialize_for_selection(cursor)?;
            let elements_len: u64 = BD::deserialize_reader(cursor)?;
            let mut elements = Vec::with_capacity(elements_len as usize);
            for _ in 0..elements_len {
                let elem: u64 = BD::deserialize_reader(cursor)?;
                elements.push(elem as usize);
            }
            let body = Box::new(deserialize_expression(cursor)?);
            Expression::For {
                selection,
                set: VariableSet { elements },
                body,
            }
        }
        38 => {
            let selection = deserialize_for_selection(cursor)?;
            let discriminant: u8 = BD::deserialize_reader(cursor)?;
            let iterator = match discriminant {
                0 => {
                    let module_expr = deserialize_module_expression(cursor)?;
                    ForIterator::ModuleIterator(module_expr)
                }
                1 => {
                    let from = Box::new(deserialize_expression(cursor)?);
                    let to = Box::new(deserialize_expression(cursor)?);
                    ForIterator::Range { from, to }
                }
                2 => {
                    let exprs_len: u64 = BD::deserialize_reader(cursor)?;
                    let mut exprs = Vec::with_capacity(exprs_len as usize);
                    for _ in 0..exprs_len {
                        exprs.push(deserialize_expression(cursor)?);
                    }
                    ForIterator::List(exprs)
                }
                _ => todo!(),
            };
            let body = Box::new(deserialize_expression(cursor)?);
            Expression::ForIdentifiers {
                selection,
                iterator,
                body,
            }
        }
        39 => {
            let selection = deserialize_for_selection(cursor)?;
            let elements_len: u64 = BD::deserialize_reader(cursor)?;
            let mut elements = Vec::with_capacity(elements_len as usize);
            for _ in 0..elements_len {
                let elem: u64 = BD::deserialize_reader(cursor)?;
                elements.push(elem as usize);
            }
            let already_matched: u64 = BD::deserialize_reader(cursor)?;
            Expression::ForRules {
                selection,
                set: RuleSet {
                    elements,
                    already_matched: already_matched as usize,
                },
            }
        }
        40 => Expression::Module(deserialize_module_expression(cursor)?),
        41 => {
            let v: u64 = BD::deserialize_reader(cursor)?;
            Expression::Rule(v as usize)
        }
        42 => {
            let v: u64 = BD::deserialize_reader(cursor)?;
            Expression::ExternalSymbol(v as usize)
        }
        43 => {
            let from = BD::deserialize_reader(cursor)?;
            let to = BD::deserialize_reader(cursor)?;
            Expression::Bytes(BytesSymbol { from, to })
        }
        44 => Expression::Regex(deserialize_regex(cursor)?),
        _ => todo!(),
    })
}

fn deserialize_variable_index(cursor: &mut Cursor<&[u8]>) -> Result<VariableIndex> {
    let v: Option<u64> = BD::deserialize_reader(cursor)?;
    Ok(VariableIndex(v.map(|v| v as usize)))
}

fn deserialize_for_selection(cursor: &mut Cursor<&[u8]>) -> Result<ForSelection> {
    let discriminant: u8 = BD::deserialize_reader(cursor)?;
    Ok(match discriminant {
        0 => ForSelection::Any,
        1 => ForSelection::All,
        2 => ForSelection::None,
        3 => {
            let expr = Box::new(deserialize_expression(cursor)?);
            let as_percent = BD::deserialize_reader(cursor)?;
            ForSelection::Expr { expr, as_percent }
        }
        _ => todo!(),
    })
}

fn deserialize_module_expression(cursor: &mut Cursor<&[u8]>) -> Result<ModuleExpression> {
    let discriminant: u8 = BD::deserialize_reader(cursor)?;
    let kind = match discriminant {
        0 => {
            let v: u64 = BD::deserialize_reader(cursor)?;
            ModuleExpressionKind::BoundedModuleValueUse {
                index: BoundedValueIndex::Module(v as usize),
            }
        }
        1 => {
            let v: u64 = BD::deserialize_reader(cursor)?;
            ModuleExpressionKind::BoundedModuleValueUse {
                index: BoundedValueIndex::BoundedStack(v as usize),
            }
        }
        _ => todo!(),
    };

    let expressions_len: u64 = BD::deserialize_reader(cursor)?;
    let mut expressions = Vec::with_capacity(expressions_len as usize);
    for _ in 0..expressions_len {
        expressions.push(deserialize_expression(cursor)?);
    }

    let operations_len: u64 = BD::deserialize_reader(cursor)?;
    let mut operations = Vec::with_capacity(operations_len as usize);
    for _ in 0..operations_len {
        let discriminant: u8 = BD::deserialize_reader(cursor)?;
        operations.push(match discriminant {
            0 => ValueOperation::Subfield(BD::deserialize_reader(cursor)?),
            1 => ValueOperation::Subscript,
            2 => {
                let v: u64 = BD::deserialize_reader(cursor)?;
                ValueOperation::FunctionCall(v as usize)
            }
            _ => todo!(),
        });
    }

    Ok(ModuleExpression {
        kind,
        operations: ModuleOperations {
            expressions,
            operations,
        },
    })
}

fn deserialize_regex(cursor: &mut Cursor<&[u8]>) -> Result<Regex> {
    let expr = BD::deserialize_reader(cursor)?;
    // FIXME error case
    Ok(Regex::from_string(expr, false, false).unwrap())
}
