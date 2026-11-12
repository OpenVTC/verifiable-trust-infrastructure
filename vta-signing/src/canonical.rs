//! RFC 8785 (JCS) serialisation and the I-JSON number rule it needs.

use serde_json::Value;

use crate::FormatRefusal;

/// `value` serialised with RFC 8785.
pub fn canonicalize(value: &Value) -> Result<String, String> {
    serde_json_canonicalizer::to_string(value).map_err(|e| e.to_string())
}

/// RFC 8785 serialises every number as an IEEE 754 double; an integer beyond
/// 2⁵³ would be rounded into a different claim, so it is refused instead.
pub fn check_i_json(value: &Value) -> Result<(), FormatRefusal> {
    const MAX_EXACT: u64 = 1 << 53;
    match value {
        Value::Number(n) => {
            let exact = n
                .as_u64()
                .map(|u| u <= MAX_EXACT)
                .or_else(|| n.as_i64().map(|i| i.unsigned_abs() <= MAX_EXACT))
                .unwrap_or(true);
            if exact {
                Ok(())
            } else {
                Err(FormatRefusal::PayloadInvalid(format!(
                    "the number {n} cannot be serialised exactly (RFC 8785); send it as a string"
                )))
            }
        }
        Value::Array(items) => items.iter().try_for_each(check_i_json),
        Value::Object(members) => members.values().try_for_each(check_i_json),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn members_are_sorted_and_whitespace_is_dropped() {
        assert_eq!(
            canonicalize(&json!({"b": 1, "a": [true, null], "c": "x"})).unwrap(),
            r#"{"a":[true,null],"b":1,"c":"x"}"#
        );
    }

    #[test]
    fn an_integer_a_double_cannot_hold_is_refused_at_any_depth() {
        let exact = json!({"n": 9_007_199_254_740_992u64, "m": -9_007_199_254_740_992i64});
        assert_eq!(check_i_json(&exact), Ok(()));

        for beyond in [
            json!({"n": 9_007_199_254_740_993u64}),
            json!([{"deep": {"n": -9_007_199_254_740_993i64}}]),
        ] {
            assert!(
                matches!(check_i_json(&beyond), Err(FormatRefusal::PayloadInvalid(_))),
                "{beyond}"
            );
        }
    }

    #[test]
    fn floats_strings_and_literals_pass() {
        assert_eq!(
            check_i_json(&json!({"f": 1.5, "s": "x", "b": false, "z": null})),
            Ok(())
        );
    }
}
