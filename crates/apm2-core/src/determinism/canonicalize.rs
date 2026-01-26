//! YAML canonicalization for deterministic output.
//!
//! This module provides functions to produce canonical YAML output that is
//! identical regardless of the input key order or formatting. This is
//! essential for reproducible builds and meaningful diffs.
//!
//! # Canonicalization Rules
//!
//! 1. All mapping keys are sorted lexicographically (byte order)
//! 2. Two-space indentation is used consistently
//! 3. No trailing whitespace on any line
//! 4. Consistent quoting: simple strings are unquoted, complex strings quoted
//! 5. Null values are represented as `null`
//!
//! # Example
//!
//! ```
//! use apm2_core::determinism::canonicalize_yaml;
//! use serde_yaml::Value;
//!
//! let yaml: Value = serde_yaml::from_str(
//!     r"
//! zebra: 1
//! apple: 2
//! ",
//! )
//! .unwrap();
//!
//! let canonical = canonicalize_yaml(&yaml);
//! assert_eq!(canonical, "apple: 2\nzebra: 1\n");
//! ```

use std::collections::BTreeMap;

use serde_yaml::Value;

/// Canonicalizes a YAML value to a deterministic string representation.
///
/// The output has the following properties:
/// - All mapping keys are sorted lexicographically
/// - Uses 2-space indentation
/// - No trailing whitespace
/// - Idempotent: `canonicalize_yaml(parse(canonicalize_yaml(v))) ==
///   canonicalize_yaml(v)`
///
/// # Arguments
///
/// * `value` - The YAML value to canonicalize
///
/// # Returns
///
/// A canonical string representation of the YAML value.
#[must_use]
pub fn canonicalize_yaml(value: &Value) -> String {
    let sorted = sort_keys_recursive(value);
    let mut output = String::new();
    emit_value(&sorted, 0, true, &mut output);
    output
}

/// Recursively sorts all mapping keys in a YAML value.
fn sort_keys_recursive(value: &Value) -> Value {
    match value {
        Value::Mapping(map) => {
            // Convert to BTreeMap for sorted iteration
            let sorted: BTreeMap<String, Value> = map
                .iter()
                .filter_map(|(k, v)| {
                    let key = yaml_key_to_string(k)?;
                    Some((key, sort_keys_recursive(v)))
                })
                .collect();

            // Convert back to a Mapping with sorted keys
            let mut result = serde_yaml::Mapping::new();
            for (key, val) in sorted {
                result.insert(Value::String(key), val);
            }
            Value::Mapping(result)
        },
        Value::Sequence(seq) => Value::Sequence(seq.iter().map(sort_keys_recursive).collect()),
        other => other.clone(),
    }
}

/// Converts a YAML key to a string for sorting purposes.
fn yaml_key_to_string(key: &Value) -> Option<String> {
    match key {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => Some("null".to_string()),
        // Complex keys are not supported for sorting
        _ => None,
    }
}

/// Emits a YAML value to the output string.
fn emit_value(value: &Value, indent: usize, at_line_start: bool, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(b) => output.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => output.push_str(&n.to_string()),
        Value::String(s) => emit_string(s, output),
        Value::Sequence(seq) => emit_sequence(seq, indent, at_line_start, output),
        Value::Mapping(map) => emit_mapping(map, indent, at_line_start, output),
        Value::Tagged(tagged) => {
            // Handle tagged values by emitting the tag and then the value
            output.push('!');
            output.push_str(&tagged.tag.to_string());
            output.push(' ');
            emit_value(&tagged.value, indent, false, output);
        },
    }
}

/// Emits a string value, quoting if necessary.
fn emit_string(s: &str, output: &mut String) {
    if needs_quoting(s) {
        emit_quoted_string(s, output);
    } else {
        output.push_str(s);
    }
}

/// Determines if a string needs to be quoted in YAML.
fn needs_quoting(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }

    // Check for reserved words
    let lower = s.to_lowercase();
    if matches!(
        lower.as_str(),
        "true" | "false" | "null" | "yes" | "no" | "on" | "off" | "~"
    ) {
        return true;
    }

    // Check for characters that require quoting
    let first = s.chars().next().unwrap();
    if first.is_ascii_digit()
        || first == '-'
        || first == '.'
        || first == '['
        || first == '{'
        || first == '!'
        || first == '&'
        || first == '*'
        || first == '\''
        || first == '"'
        || first == '|'
        || first == '>'
        || first == '%'
        || first == '@'
        || first == '`'
    {
        return true;
    }

    // Check for special characters anywhere in the string
    s.contains(':')
        || s.contains('#')
        || s.contains('\n')
        || s.contains('\r')
        || s.contains('\t')
        || s.starts_with(' ')
        || s.ends_with(' ')
        || s.contains("  ")
}

/// Emits a double-quoted string with proper escaping.
fn emit_quoted_string(s: &str, output: &mut String) {
    use std::fmt::Write;
    output.push('"');
    for c in s.chars() {
        match c {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if c.is_control() => {
                let code = c as u32;
                let _ = write!(output, "\\u{code:04x}");
            },
            c => output.push(c),
        }
    }
    output.push('"');
}

/// Emits a sequence (array) value.
fn emit_sequence(seq: &[Value], indent: usize, at_line_start: bool, output: &mut String) {
    if seq.is_empty() {
        output.push_str("[]");
        return;
    }

    // For sequences that are not at the start of a line, we need a newline first
    if !at_line_start {
        output.push('\n');
    }

    for item in seq {
        // Add indent
        for _ in 0..indent {
            output.push_str("  ");
        }
        output.push_str("- ");

        // Check if item is a mapping - if so, emit first key on same line
        if let Value::Mapping(map) = item {
            if map.is_empty() {
                output.push_str("{}");
            } else {
                emit_mapping_inline_first(map, indent + 1, output);
            }
        } else {
            emit_value(item, indent + 1, false, output);
        }

        // Ensure each item ends with a newline
        if !output.ends_with('\n') {
            output.push('\n');
        }
    }
}

/// Emits a mapping's first key-value on the current line, rest indented below.
fn emit_mapping_inline_first(map: &serde_yaml::Mapping, indent: usize, output: &mut String) {
    let mut first = true;
    for (key, val) in map {
        if first {
            first = false;
            // Emit first key-value on current line
            emit_value(key, indent, false, output);
        } else {
            // Emit subsequent key-values on new lines with indent
            for _ in 0..indent {
                output.push_str("  ");
            }
            emit_value(key, indent, true, output);
        }

        // Common code for all key-value pairs
        output.push(':');
        if is_scalar(val) {
            output.push(' ');
            emit_value(val, indent, false, output);
            output.push('\n');
        } else {
            emit_value(val, indent, false, output);
        }
    }
}

/// Emits a mapping (object) value.
fn emit_mapping(
    map: &serde_yaml::Mapping,
    indent: usize,
    at_line_start: bool,
    output: &mut String,
) {
    if map.is_empty() {
        output.push_str("{}");
        return;
    }

    // For mappings that are not at the start of a line, we need a newline first
    if !at_line_start {
        output.push('\n');
    }

    for (key, val) in map {
        // Add indent
        for _ in 0..indent {
            output.push_str("  ");
        }
        emit_value(key, indent, true, output);
        output.push(':');

        if is_scalar(val) {
            output.push(' ');
            emit_value(val, indent + 1, false, output);
            output.push('\n');
        } else {
            emit_value(val, indent + 1, false, output);
        }
    }
}

/// Returns true if the value is a scalar (not a collection).
#[allow(clippy::missing_const_for_fn)] // matches! on Value is not const-compatible
fn is_scalar(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    pub fn test_canonicalize_idempotent() {
        let inputs = [
            r"
zebra: 1
apple: 2
mango: 3
",
            r"
nested:
  z_key: value
  a_key: value
  m_key:
    deep_z: 1
    deep_a: 2
",
            r"
list:
  - c: 3
    a: 1
    b: 2
  - single: value
",
        ];

        for input in &inputs {
            let value: Value = serde_yaml::from_str(input).unwrap();
            let canonical1 = canonicalize_yaml(&value);
            let reparsed: Value = serde_yaml::from_str(&canonical1).unwrap();
            let canonical2 = canonicalize_yaml(&reparsed);
            assert_eq!(
                canonical1, canonical2,
                "Canonicalization should be idempotent"
            );
        }
    }

    #[test]
    pub fn test_nested_key_sorting() {
        let input = r"
outer:
  zebra: 1
  apple: 2
  nested:
    zoo: deep
    ant: value
";
        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value);

        // Verify outer keys are sorted
        let apple_pos = canonical.find("apple:").unwrap();
        let nested_pos = canonical.find("nested:").unwrap();
        let zebra_pos = canonical.find("zebra:").unwrap();
        assert!(
            apple_pos < nested_pos,
            "apple should come before nested: apple_pos={apple_pos}, nested_pos={nested_pos}",
        );
        assert!(
            nested_pos < zebra_pos,
            "nested should come before zebra: nested_pos={nested_pos}, zebra_pos={zebra_pos}",
        );

        // Verify nested keys are sorted
        let ant_pos = canonical.find("ant:").unwrap();
        let zoo_pos = canonical.find("zoo:").unwrap();
        assert!(
            ant_pos < zoo_pos,
            "ant should come before zoo: ant_pos={ant_pos}, zoo_pos={zoo_pos}",
        );
    }

    #[test]
    fn test_two_space_indent() {
        let input = r"
parent:
  child:
    grandchild: value
";
        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value);

        // Check that grandchild is indented with 4 spaces (2 levels * 2 spaces)
        assert!(
            canonical.contains("    grandchild:"),
            "Expected 4-space indent for grandchild, got:\n{canonical}",
        );
    }

    #[test]
    fn test_no_trailing_whitespace() {
        let input = r"
key1: value1
key2: value2
nested:
  inner: value
";
        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value);

        for (i, line) in canonical.lines().enumerate() {
            assert!(
                !line.ends_with(' ') && !line.ends_with('\t'),
                "Line {} has trailing whitespace: {line:?}",
                i + 1,
            );
        }
    }

    #[test]
    fn test_empty_mapping() {
        let value = Value::Mapping(serde_yaml::Mapping::new());
        let canonical = canonicalize_yaml(&value);
        assert_eq!(canonical, "{}");
    }

    #[test]
    fn test_empty_sequence() {
        let value = Value::Sequence(vec![]);
        let canonical = canonicalize_yaml(&value);
        assert_eq!(canonical, "[]");
    }

    #[test]
    fn test_null_value() {
        let input = "key: null";
        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value);
        assert_eq!(canonical, "key: null\n");
    }

    #[test]
    fn test_boolean_values() {
        let input = r"
yes_val: true
no_val: false
";
        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value);
        assert!(canonical.contains("no_val: false"));
        assert!(canonical.contains("yes_val: true"));
    }

    #[test]
    fn test_string_quoting() {
        // Strings that need quoting
        let cases = [
            ("key: 'true'", "key: \"true\"\n"), // Reserved word
            ("key: ''", "key: \"\"\n"),         // Empty string
            ("key: 'hello world: test'", "key: \"hello world: test\"\n"), // Contains colon
        ];

        for (input, expected) in &cases {
            let value: Value = serde_yaml::from_str(input).unwrap();
            let canonical = canonicalize_yaml(&value);
            assert_eq!(
                &canonical, expected,
                "Input {input:?} should produce {expected:?}, got {canonical:?}",
            );
        }
    }

    #[test]
    fn test_sequence_of_mappings() {
        let input = r"
items:
  - z: 3
    a: 1
    m: 2
  - single: value
";
        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value);

        // Verify keys in each mapping are sorted
        let a_pos = canonical.find("a:").unwrap();
        let m_pos = canonical.find("m:").unwrap();
        let z_pos = canonical.find("z:").unwrap();
        assert!(a_pos < m_pos, "a should come before m");
        assert!(m_pos < z_pos, "m should come before z");
    }

    #[test]
    fn test_different_input_same_output() {
        let input1 = r"
b: 2
a: 1
";
        let input2 = r"
a: 1
b: 2
";
        let value1: Value = serde_yaml::from_str(input1).unwrap();
        let value2: Value = serde_yaml::from_str(input2).unwrap();
        let canonical1 = canonicalize_yaml(&value1);
        let canonical2 = canonicalize_yaml(&value2);

        assert_eq!(
            canonical1, canonical2,
            "Same content with different key order should produce identical output"
        );
    }

    #[test]
    fn test_multiline_string_escaping() {
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            Value::String("key".to_string()),
            Value::String("line1\nline2\nline3".to_string()),
        );
        let value = Value::Mapping(map);
        let canonical = canonicalize_yaml(&value);

        // Should be quoted with escaped newlines
        assert!(
            canonical.contains("\\n"),
            "Multiline strings should have escaped newlines"
        );
    }

    #[test]
    fn test_numeric_values() {
        let input = r"
integer: 42
float: 3.14
negative: -10
";
        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value);

        assert!(canonical.contains("float: 3.14"));
        assert!(canonical.contains("integer: 42"));
        assert!(canonical.contains("negative: -10"));
    }

    #[test]
    fn test_deeply_nested_structure() {
        let input = r"
level1:
  level2:
    level3:
      level4:
        value: deep
";
        let value: Value = serde_yaml::from_str(input).unwrap();
        let canonical = canonicalize_yaml(&value);

        // Verify proper indentation at each level
        assert!(canonical.contains("level1:\n"));
        assert!(canonical.contains("  level2:\n"));
        assert!(canonical.contains("    level3:\n"));
        assert!(canonical.contains("      level4:\n"));
        assert!(canonical.contains("        value: deep"));
    }
}
