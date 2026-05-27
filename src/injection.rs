use std::collections::HashMap;

pub fn is_valid_env_name(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

pub fn derive_env_name(secret_name: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut last_was_underscore = false;

    for c in secret_name.chars() {
        let next = if c.is_ascii_alphanumeric() {
            Some(c.to_ascii_uppercase())
        } else if c == '_' || c == '-' || c == '.' || c == '/' {
            Some('_')
        } else {
            None
        };

        if let Some(c) = next {
            if c == '_' {
                if !out.is_empty() && !last_was_underscore {
                    out.push(c);
                }
                last_was_underscore = true;
            } else {
                out.push(c);
                last_was_underscore = false;
            }
        }
    }

    while out.ends_with('_') {
        out.pop();
    }

    if out.is_empty() {
        return Err(format!(
            "could not derive an environment variable name from secret '{secret_name}'"
        ));
    }

    if out
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        out.insert(0, '_');
    }

    Ok(out)
}

pub fn collect_unique_pairs<I>(
    pairs: I,
    field_name: &str,
    value_label: &str,
) -> Result<HashMap<String, String>, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut out = HashMap::new();
    for (key, value) in pairs {
        if let Some(existing) = out.get(&key) {
            if existing == &value {
                continue;
            }
            return Err(format!(
                "conflicting duplicate {field_name} for '{key}': existing {value_label} '{existing}', new {value_label} '{value}'"
            ));
        }
        out.insert(key, value);
    }
    Ok(out)
}
