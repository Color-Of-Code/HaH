use winnow::Parser;
use winnow::Result;
use winnow::ascii::{dec_int, space0};
use winnow::combinator::{alt, delimited, opt, preceded, separated};
use winnow::token::{take_till, take_while};

use crate::expr::Expression;
use crate::pipeline::RuleValue;

// ── Condition expression (compact syntax) ─────────────────────────────────────

/// Parsed result of a compact condition expression like `"$x > 0"`.
#[derive(Debug, Clone, PartialEq)]
pub enum ConditionExpr {
    /// Comparison: `lhs_expr OP rhs_expr` (e.g. `"$count > 0"`)
    Compare {
        lhs: String,
        op: CompareToken,
        rhs: String,
    },
    /// Bare expression (no operator) → implies non-empty check.
    Bare(String),
}

/// Comparison operator token parsed from a compact condition string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareToken {
    Gte,
    Lte,
    Neq,
    Eq,
    Gt,
    Lt,
    Match,
}

/// Parse a compact condition expression string.
///
/// Splits on comparison operators (trying longest first: `>=`, `<=`, `!=`,
/// `==`, `=~`, `>`, `<`).  If no operator is found, returns [`ConditionExpr::Bare`].
pub fn parse_condition_expr(input: &str) -> ConditionExpr {
    // Operators ordered longest-first to avoid `>` matching inside `>=`.
    const OPS: &[(&str, CompareToken)] = &[
        (">=", CompareToken::Gte),
        ("<=", CompareToken::Lte),
        ("!=", CompareToken::Neq),
        ("==", CompareToken::Eq),
        ("=~", CompareToken::Match),
        (">", CompareToken::Gt),
        ("<", CompareToken::Lt),
    ];
    for &(tok, op) in OPS {
        if let Some(pos) = find_operator(input, tok) {
            let lhs = input[..pos].trim().to_string();
            let rhs = input[pos + tok.len()..].trim().to_string();
            return ConditionExpr::Compare { lhs, op, rhs };
        }
    }
    ConditionExpr::Bare(input.trim().to_string())
}

/// Find an operator token that is NOT inside quotes.
fn find_operator(input: &str, op: &str) -> Option<usize> {
    let mut in_quote: Option<char> = None;
    let bytes = input.as_bytes();
    for i in 0..bytes.len() {
        let ch = bytes[i] as char;
        match in_quote {
            Some(q) if ch == q => in_quote = None,
            Some(_) => {}
            None if ch == '\'' || ch == '"' => in_quote = Some(ch),
            None if input[i..].starts_with(op) => return Some(i),
            None => {}
        }
    }
    None
}

/// Parse a full pipeline expression.
pub fn parse_expression(input: &mut &str) -> Result<Expression> {
    let mut exprs: Vec<Expression> =
        separated(1.., parse_single_expression, (space0, '|', space0)).parse_next(input)?;

    if exprs.len() == 1 {
        Ok(exprs.remove(0))
    } else {
        Ok(Expression::Pipeline(exprs))
    }
}

fn parse_single_expression(input: &mut &str) -> Result<Expression> {
    alt((
        parse_variable,
        parse_bool_literal,
        parse_string_literal,
        parse_int_literal,
        parse_filter_call,
    ))
    .parse_next(input)
}

/// Parse a bare string for eval_expr that may contain spaces.
pub fn parse_eval_expr(input: &mut &str) -> Result<Expression> {
    if !input.contains('|') && !input.contains('$') && !input.contains('(') {
        if let Ok(n) = input.trim().parse::<i64>() {
            *input = "";
            return Ok(Expression::Literal(RuleValue::Int(n)));
        }
        if input.trim() == "true" {
            *input = "";
            return Ok(Expression::Literal(RuleValue::Bool(true)));
        }
        if input.trim() == "false" {
            *input = "";
            return Ok(Expression::Literal(RuleValue::Bool(false)));
        }
        let s = input.trim();
        *input = "";
        return Ok(Expression::Literal(RuleValue::Str(s.to_string())));
    }

    alt((
        parse_expression,
        take_while(1.., |_| true)
            .map(|s: &str| Expression::Literal(RuleValue::Str(s.trim().to_string()))),
    ))
    .parse_next(input)
}

fn parse_variable(input: &mut &str) -> Result<Expression> {
    preceded(
        '$',
        take_while(1.., |c: char| c.is_alphanumeric() || c == '_' || c == '.'),
    )
    .map(|name: &str| Expression::Variable(name.to_string()))
    .parse_next(input)
}

fn parse_string_literal(input: &mut &str) -> Result<Expression> {
    alt((
        delimited('\'', take_till(0.., '\''), '\''),
        delimited('"', take_till(0.., '"'), '"'),
    ))
    .map(|s: &str| Expression::Literal(RuleValue::Str(s.to_string())))
    .parse_next(input)
}

fn parse_int_literal(input: &mut &str) -> Result<Expression> {
    dec_int
        .map(|n: i64| Expression::Literal(RuleValue::Int(n)))
        .parse_next(input)
}

fn parse_bool_literal(input: &mut &str) -> Result<Expression> {
    alt(("true".value(true), "false".value(false)))
        .map(|b| Expression::Literal(RuleValue::Bool(b)))
        .parse_next(input)
}

fn parse_filter_call(input: &mut &str) -> Result<Expression> {
    let name = (
        take_while(1, |c: char| c.is_ascii_alphabetic() || c == '_'),
        take_while(0.., |c: char| c.is_alphanumeric() || c == '_'),
    )
        .map(|(first, rest): (&str, &str)| format!("{}{}", first, rest))
        .parse_next(input)?;

    let args = opt(delimited(
        '(',
        separated(0.., parse_single_expression, (space0, ',', space0)),
        ')',
    ))
    .parse_next(input)?;

    Ok(Expression::Filter {
        name,
        args: args.unwrap_or_default(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_condition_gt() {
        let result = parse_condition_expr("$count > 0");
        assert_eq!(
            result,
            ConditionExpr::Compare {
                lhs: "$count".into(),
                op: CompareToken::Gt,
                rhs: "0".into(),
            }
        );
    }

    #[test]
    fn parse_condition_gte() {
        let result = parse_condition_expr("$x >= 10");
        assert_eq!(
            result,
            ConditionExpr::Compare {
                lhs: "$x".into(),
                op: CompareToken::Gte,
                rhs: "10".into(),
            }
        );
    }

    #[test]
    fn parse_condition_lte_with_variable_rhs() {
        let result = parse_condition_expr("$free_mb <= $threshold_mb");
        assert_eq!(
            result,
            ConditionExpr::Compare {
                lhs: "$free_mb".into(),
                op: CompareToken::Lte,
                rhs: "$threshold_mb".into(),
            }
        );
    }

    #[test]
    fn parse_condition_eq_bool() {
        let result = parse_condition_expr("$active == true");
        assert_eq!(
            result,
            ConditionExpr::Compare {
                lhs: "$active".into(),
                op: CompareToken::Eq,
                rhs: "true".into(),
            }
        );
    }

    #[test]
    fn parse_condition_neq() {
        let result = parse_condition_expr("$status != false");
        assert_eq!(
            result,
            ConditionExpr::Compare {
                lhs: "$status".into(),
                op: CompareToken::Neq,
                rhs: "false".into(),
            }
        );
    }

    #[test]
    fn parse_condition_bare_variable() {
        let result = parse_condition_expr("$items");
        assert_eq!(result, ConditionExpr::Bare("$items".into()));
    }

    #[test]
    fn parse_condition_bare_pipeline() {
        let result = parse_condition_expr("$output | lines | non_empty");
        assert_eq!(
            result,
            ConditionExpr::Bare("$output | lines | non_empty".into())
        );
    }

    #[test]
    fn parse_condition_operator_in_quotes_not_matched() {
        let result = parse_condition_expr("$x == '> 5'");
        assert_eq!(
            result,
            ConditionExpr::Compare {
                lhs: "$x".into(),
                op: CompareToken::Eq,
                rhs: "'> 5'".into(),
            }
        );
    }

    #[test]
    fn parse_condition_regex_match() {
        let result = parse_condition_expr("$status =~ '^overlap:'");
        assert_eq!(
            result,
            ConditionExpr::Compare {
                lhs: "$status".into(),
                op: CompareToken::Match,
                rhs: "'^overlap:'".into(),
            }
        );
    }
}
