use winnow::Parser;
use winnow::Result;
use winnow::ascii::{alphanumeric1, dec_int, space0};
use winnow::combinator::{alt, delimited, opt, preceded, separated};
use winnow::token::{take_till, take_while};

use crate::expr::Expression;
use crate::pipeline::RuleValue;

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
        parse_literal,
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
    preceded('$', alphanumeric1)
        .map(|name: &str| Expression::Variable(name.to_string()))
        .parse_next(input)
}

fn parse_literal(input: &mut &str) -> Result<Expression> {
    alt((parse_string_literal, parse_int_literal, parse_bool_literal)).parse_next(input)
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
    let name = take_while(1.., |c: char| c.is_alphanumeric() || c == '_').parse_next(input)?;

    let args = opt(delimited(
        '(',
        separated(0.., parse_single_expression, (space0, ',', space0)),
        ')',
    ))
    .parse_next(input)?;

    Ok(Expression::Filter {
        name: name.to_string(),
        args: args.unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_parse_variable() {
        let mut input = "$stdout";
        assert_eq!(
            parse_expression(&mut input).unwrap(),
            Expression::Variable("stdout".to_string())
        );
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn test_parse_pipeline() {
        let mut input = "$stdout | lines | nth(1)";
        let expr = parse_expression(&mut input).unwrap();
        match expr {
            Expression::Pipeline(parts) => {
                assert_eq!(parts.len(), 3);
                assert_eq!(parts[0], Expression::Variable("stdout".to_string()));
                assert_eq!(
                    parts[1],
                    Expression::Filter {
                        name: "lines".to_string(),
                        args: vec![]
                    }
                );
                match &parts[2] {
                    Expression::Filter { name, args } => {
                        assert_eq!(name, "nth");
                        assert_eq!(args.len(), 1);
                        assert_eq!(args[0], Expression::Literal(RuleValue::Int(1)));
                    }
                    _ => panic!("Expected filter"),
                }
            }
            _ => panic!("Expected pipeline"),
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_parse_literals() {
        let mut input = "'foo'";
        assert_eq!(
            parse_expression(&mut input).unwrap(),
            Expression::Literal(RuleValue::Str("foo".to_string()))
        );

        let mut input = "42";
        assert_eq!(
            parse_expression(&mut input).unwrap(),
            Expression::Literal(RuleValue::Int(42))
        );

        let mut input = "true";
        assert_eq!(
            parse_expression(&mut input).unwrap(),
            Expression::Literal(RuleValue::Bool(true))
        );
    }
}
