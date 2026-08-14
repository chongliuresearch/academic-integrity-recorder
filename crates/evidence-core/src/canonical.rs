use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::Value;
use std::cmp::Ordering;

/// Serialize JSON with deterministic key ordering compatible with RFC 8785's
/// UTF-16 property-name ordering. serde_json uses Ryu for finite numbers.
pub fn to_jcs<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    let mut output = String::new();
    write_value(&value, &mut output)?;
    Ok(output.into_bytes())
}

fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn write_value(value: &Value, output: &mut String) -> Result<()> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => {
            const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
            if value
                .as_u64()
                .is_some_and(|number| number > MAX_SAFE_INTEGER)
                || value
                    .as_i64()
                    .is_some_and(|number| number < -(MAX_SAFE_INTEGER as i64))
            {
                bail!("integer exceeds the interoperable I-JSON range; encode it as a string");
            }
            let encoded = value.to_string();
            if encoded == "NaN" || encoded.contains("inf") {
                bail!("non-finite numbers are not valid I-JSON");
            }
            output.push_str(&encoded);
        }
        Value::String(value) => output.push_str(&serde_json::to_string(value)?),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_value(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| utf16_cmp(left, right));
            output.push('{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key)?);
                output.push(':');
                write_value(value, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::to_jcs;
    use serde_json::json;

    #[test]
    fn sorts_and_removes_whitespace() {
        let encoded = to_jcs(&json!({"z": 1, "a": [true, "x"]})).unwrap();
        assert_eq!(
            String::from_utf8(encoded).unwrap(),
            r#"{"a":[true,"x"],"z":1}"#
        );
    }

    #[test]
    fn uses_utf16_key_order() {
        let encoded = to_jcs(&json!({"\u{1f600}": 1, "\u{e000}": 2})).unwrap();
        assert_eq!(String::from_utf8(encoded).unwrap(), "{\"😀\":1,\"\":2}");
    }

    #[test]
    fn matches_rfc_8785_number_sample_and_rejects_non_interoperable_integer() {
        let encoded = to_jcs(&json!({
            "numbers": [333333333.3333333_f64, 1e30_f64, 4.5_f64, 0.002_f64, 1e-27_f64]
        }))
        .unwrap();
        assert_eq!(
            String::from_utf8(encoded).unwrap(),
            r#"{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}"#
        );
        assert!(to_jcs(&json!({"unsafe": 9_007_199_254_740_992_u64})).is_err());
    }
}
