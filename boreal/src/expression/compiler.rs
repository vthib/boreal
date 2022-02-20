//! Compilation of a parsed expression into an optimized one.
use super::{parser, Expression, ForIterator, ForSelection, Identifier};

pub struct Compiler;

impl Compiler {
    #[allow(clippy::too_many_lines)]
    pub fn compile_expression(&self, expression: parser::Expression) -> Result<Expression, ()> {
        match expression {
            parser::Expression::Filesize => Ok(Expression::Filesize),
            parser::Expression::Entrypoint => Ok(Expression::Entrypoint),
            parser::Expression::ReadInteger {
                size,
                unsigned,
                big_endian,
                addr,
            } => Ok(Expression::ReadInteger {
                size,
                unsigned,
                big_endian,
                addr: Box::new(self.compile_expression(*addr)?),
            }),

            parser::Expression::Number(v) => Ok(Expression::Number(v)),

            parser::Expression::Double(v) => Ok(Expression::Double(v)),

            parser::Expression::Count(variable_name) => Ok(Expression::Count(variable_name)),

            parser::Expression::CountInRange {
                variable_name,
                from,
                to,
            } => Ok(Expression::CountInRange {
                variable_name,
                from: Box::new(self.compile_expression(*from)?),
                to: Box::new(self.compile_expression(*to)?),
            }),

            parser::Expression::Offset {
                variable_name,
                occurence_number,
            } => Ok(Expression::Offset {
                variable_name,
                occurence_number: Box::new(self.compile_expression(*occurence_number)?),
            }),

            parser::Expression::Length {
                variable_name,
                occurence_number,
            } => Ok(Expression::Length {
                variable_name,
                occurence_number: Box::new(self.compile_expression(*occurence_number)?),
            }),

            parser::Expression::Neg(expr) => {
                Ok(Expression::Neg(Box::new(self.compile_expression(*expr)?)))
            }

            parser::Expression::Add(left, right) => Ok(Expression::Add(
                Box::new(self.compile_expression(*left)?),
                Box::new(self.compile_expression(*right)?),
            )),
            parser::Expression::Sub(left, right) => Ok(Expression::Sub(
                Box::new(self.compile_expression(*left)?),
                Box::new(self.compile_expression(*right)?),
            )),
            parser::Expression::Mul(left, right) => Ok(Expression::Mul(
                Box::new(self.compile_expression(*left)?),
                Box::new(self.compile_expression(*right)?),
            )),
            parser::Expression::Div(left, right) => Ok(Expression::Div(
                Box::new(self.compile_expression(*left)?),
                Box::new(self.compile_expression(*right)?),
            )),

            parser::Expression::Mod(left, right) => Ok(Expression::Mod(
                Box::new(self.compile_expression(*left)?),
                Box::new(self.compile_expression(*right)?),
            )),

            parser::Expression::BitwiseXor(left, right) => Ok(Expression::BitwiseXor(
                Box::new(self.compile_expression(*left)?),
                Box::new(self.compile_expression(*right)?),
            )),
            parser::Expression::BitwiseAnd(left, right) => Ok(Expression::BitwiseAnd(
                Box::new(self.compile_expression(*left)?),
                Box::new(self.compile_expression(*right)?),
            )),
            parser::Expression::BitwiseOr(left, right) => Ok(Expression::BitwiseOr(
                Box::new(self.compile_expression(*left)?),
                Box::new(self.compile_expression(*right)?),
            )),

            parser::Expression::BitwiseNot(expr) => Ok(Expression::BitwiseNot(Box::new(
                self.compile_expression(*expr)?,
            ))),

            parser::Expression::ShiftLeft(left, right) => Ok(Expression::ShiftLeft(
                Box::new(self.compile_expression(*left)?),
                Box::new(self.compile_expression(*right)?),
            )),
            parser::Expression::ShiftRight(left, right) => Ok(Expression::ShiftRight(
                Box::new(self.compile_expression(*left)?),
                Box::new(self.compile_expression(*right)?),
            )),

            parser::Expression::And(left, right) => Ok(Expression::And(
                Box::new(self.compile_expression(*left)?),
                Box::new(self.compile_expression(*right)?),
            )),
            parser::Expression::Or(left, right) => Ok(Expression::Or(
                Box::new(self.compile_expression(*left)?),
                Box::new(self.compile_expression(*right)?),
            )),

            parser::Expression::Not(expr) => {
                Ok(Expression::Not(Box::new(self.compile_expression(*expr)?)))
            }

            parser::Expression::Cmp {
                left,
                right,
                less_than,
                can_be_equal,
            } => Ok(Expression::Cmp {
                left: Box::new(self.compile_expression(*left)?),
                right: Box::new(self.compile_expression(*right)?),
                less_than,
                can_be_equal,
            }),

            parser::Expression::Eq(left, right) => Ok(Expression::Eq(
                Box::new(self.compile_expression(*left)?),
                Box::new(self.compile_expression(*right)?),
            )),

            parser::Expression::Contains {
                haystack,
                needle,
                case_insensitive,
            } => Ok(Expression::Contains {
                haystack: Box::new(self.compile_expression(*haystack)?),
                needle: Box::new(self.compile_expression(*needle)?),
                case_insensitive,
            }),

            parser::Expression::StartsWith {
                expr,
                prefix,
                case_insensitive,
            } => Ok(Expression::StartsWith {
                expr: Box::new(self.compile_expression(*expr)?),
                prefix: Box::new(self.compile_expression(*prefix)?),
                case_insensitive,
            }),

            parser::Expression::EndsWith {
                expr,
                suffix,
                case_insensitive,
            } => Ok(Expression::EndsWith {
                expr: Box::new(self.compile_expression(*expr)?),
                suffix: Box::new(self.compile_expression(*suffix)?),
                case_insensitive,
            }),

            parser::Expression::IEquals(left, right) => Ok(Expression::IEquals(
                Box::new(self.compile_expression(*left)?),
                Box::new(self.compile_expression(*right)?),
            )),

            parser::Expression::Matches(expr, regex) => Ok(Expression::Matches(
                Box::new(self.compile_expression(*expr)?),
                regex,
            )),

            parser::Expression::Defined(expr) => Ok(Expression::Defined(Box::new(
                self.compile_expression(*expr)?,
            ))),

            parser::Expression::Boolean(b) => Ok(Expression::Boolean(b)),

            parser::Expression::Variable(variable_name) => Ok(Expression::Variable(variable_name)),

            parser::Expression::VariableAt(variable_name, expr_offset) => {
                Ok(Expression::VariableAt(
                    variable_name,
                    Box::new(self.compile_expression(*expr_offset)?),
                ))
            }

            parser::Expression::VariableIn {
                variable_name,
                from,
                to,
            } => Ok(Expression::VariableIn {
                variable_name,
                from: Box::new(self.compile_expression(*from)?),
                to: Box::new(self.compile_expression(*to)?),
            }),

            parser::Expression::For {
                selection,
                set,
                body,
            } => Ok(Expression::For {
                selection: self.compile_for_selection(selection)?,
                set,
                body: match body {
                    Some(body) => Some(Box::new(self.compile_expression(*body)?)),
                    None => None,
                },
            }),

            parser::Expression::ForIn {
                selection,
                set,
                from,
                to,
            } => Ok(Expression::ForIn {
                selection: self.compile_for_selection(selection)?,
                set,
                from: Box::new(self.compile_expression(*from)?),
                to: Box::new(self.compile_expression(*to)?),
            }),

            parser::Expression::ForIdentifiers {
                selection,

                identifiers,

                iterator,

                body,
            } => Ok(Expression::ForIdentifiers {
                selection: self.compile_for_selection(selection)?,
                identifiers,
                iterator: self.compile_for_iterator(iterator)?,
                body: Box::new(self.compile_expression(*body)?),
            }),

            parser::Expression::Identifier(identifier) => {
                Ok(Expression::Identifier(self.compile_identifier(identifier)?))
            }
            parser::Expression::String(s) => Ok(Expression::String(s)),
            parser::Expression::Regex(regex) => Ok(Expression::Regex(regex)),
        }
    }

    fn compile_identifier(&self, identifier: parser::Identifier) -> Result<Identifier, ()> {
        match identifier {
            parser::Identifier::Raw(s) => Ok(Identifier::Raw(s)),
            parser::Identifier::Subscript {
                identifier,
                subscript,
            } => Ok(Identifier::Subscript {
                identifier: Box::new(self.compile_identifier(*identifier)?),
                subscript: Box::new(self.compile_expression(*subscript)?),
            }),
            parser::Identifier::Subfield {
                identifier,
                subfield,
            } => Ok(Identifier::Subfield {
                identifier: Box::new(self.compile_identifier(*identifier)?),
                subfield,
            }),
            parser::Identifier::FunctionCall {
                identifier,
                arguments,
            } => {
                let arguments: Result<Vec<_>, _> = arguments
                    .into_iter()
                    .map(|expr| self.compile_expression(expr))
                    .collect();
                Ok(Identifier::FunctionCall {
                    identifier: Box::new(self.compile_identifier(*identifier)?),
                    arguments: arguments?,
                })
            }
        }
    }

    fn compile_for_selection(&self, selection: parser::ForSelection) -> Result<ForSelection, ()> {
        match selection {
            parser::ForSelection::Any => Ok(ForSelection::Any),
            parser::ForSelection::All => Ok(ForSelection::All),
            parser::ForSelection::None => Ok(ForSelection::None),
            parser::ForSelection::Expr { expr, as_percent } => Ok(ForSelection::Expr {
                expr: Box::new(self.compile_expression(*expr)?),
                as_percent,
            }),
        }
    }

    fn compile_for_iterator(&self, selection: parser::ForIterator) -> Result<ForIterator, ()> {
        match selection {
            parser::ForIterator::Identifier(identifier) => Ok(ForIterator::Identifier(
                self.compile_identifier(identifier)?,
            )),
            parser::ForIterator::Range { from, to } => Ok(ForIterator::Range {
                from: Box::new(self.compile_expression(*from)?),
                to: Box::new(self.compile_expression(*to)?),
            }),
            parser::ForIterator::List(exprs) => Ok(ForIterator::List(
                exprs
                    .into_iter()
                    .map(|expr| self.compile_expression(expr))
                    .collect::<Result<Vec<_>, _>>()?,
            )),
        }
    }
}
