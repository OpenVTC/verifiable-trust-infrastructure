//! Whether a value fits its field: its type's shape (`directory-card`
//! `FieldValue`) and the field's constraints.

use serde_json::Value;

use super::model::{FieldDef, FieldType};

/// Why a value does not fit, for `valueInvalid`'s `reason`.
pub type Unfit = String;

fn chars(s: &str) -> u64 {
    s.chars().count() as u64
}

fn check_text(field: &FieldDef, s: &str) -> Result<(), Unfit> {
    if let Some(max) = field.constraint_u64("maxLength")
        && chars(s) > max
    {
        return Err(format!("longer than {max} characters"));
    }
    if let Some(min) = field.constraint_u64("minLength")
        && chars(s) < min
    {
        return Err(format!("shorter than {min} characters"));
    }
    if let Some(p) = field
        .constraints
        .as_ref()
        .and_then(|c| c.get("pattern"))
        .and_then(Value::as_str)
    {
        let re =
            regress::Regex::new(p).map_err(|_| "the field's pattern is unusable".to_string())?;
        if re.find(s).is_none() {
            return Err("does not match the field's pattern".into());
        }
    }
    if s.chars().any(|c| c.is_control() && c != '\n') {
        return Err("contains control characters".into());
    }
    Ok(())
}

/// An absolute `https` or `http` URL with a host. A link is shown to other
/// members, so nothing else — `javascript:`, `data:`, a bare path — passes.
fn check_url(s: &str) -> Result<(), Unfit> {
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .ok_or("not an http or https URL")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    if host.is_empty()
        || host.starts_with(':')
        || s.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err("not an http or https URL".into());
    }
    Ok(())
}

fn check_scalar(field: &FieldDef, s: &str) -> Result<(), Unfit> {
    match field.kind {
        FieldType::Text | FieldType::LongText => {
            if field.kind == FieldType::Text && s.contains('\n') {
                return Err("a single line of text".into());
            }
            check_text(field, s)
        }
        FieldType::Url => {
            check_text(field, s)?;
            check_url(s)
        }
        FieldType::Email => {
            check_text(field, s)?;
            let (local, domain) = s.split_once('@').ok_or("not an email address")?;
            if local.is_empty()
                || !domain.contains('.')
                || domain.contains('@')
                || s.chars().any(char::is_whitespace)
                || s.len() > 254
            {
                return Err("not an email address".into());
            }
            Ok(())
        }
        FieldType::Phone => {
            check_text(field, s)?;
            let digits = s.chars().filter(char::is_ascii_digit).count();
            let allowed = s
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, '+' | ' ' | '-' | '(' | ')' | '.'));
            if !allowed || !(3..=20).contains(&digits) {
                return Err("not a telephone number".into());
            }
            Ok(())
        }
        FieldType::Date => {
            let d = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
                .map_err(|_| "not a date (YYYY-MM-DD)".to_string())?;
            let bound = |name: &str| {
                field
                    .constraints
                    .as_ref()
                    .and_then(|c| c.get(name))
                    .and_then(Value::as_str)
                    .and_then(|b| chrono::NaiveDate::parse_from_str(b, "%Y-%m-%d").ok())
            };
            if bound("minDate").is_some_and(|m| d < m) || bound("maxDate").is_some_and(|m| d > m) {
                return Err("outside the field's dates".into());
            }
            Ok(())
        }
        FieldType::Country => {
            if s.len() == 2 && s.chars().all(|c| c.is_ascii_uppercase()) {
                Ok(())
            } else {
                Err("not an ISO 3166-1 alpha-2 country code".into())
            }
        }
        FieldType::Did => {
            vti_common::identifier::validate_did(&field.key, s).map_err(|_| "not a DID".to_string())
        }
        FieldType::Enum => {
            if field.options().iter().any(|o| o == s) {
                Ok(())
            } else {
                Err("not one of the field's options".into())
            }
        }
        FieldType::MultiEnum | FieldType::Image | FieldType::Claim => {
            Err("not a value of this field's type".into())
        }
    }
}

fn check_list(field: &FieldDef, items: &[Value]) -> Result<(), Unfit> {
    let max = field.constraint_u64("maxItems").unwrap_or(32);
    if items.len() as u64 > max {
        return Err(format!("more than {max} items"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for item in items {
        let s = item.as_str().ok_or("a list of strings")?;
        if !seen.insert(s) {
            return Err(format!("`{s}` is listed twice"));
        }
        if field.kind == FieldType::MultiEnum {
            if !field.options().iter().any(|o| o == s) {
                return Err(format!("`{s}` is not one of the field's options"));
            }
        } else {
            check_text(field, s)?;
            check_url(s)?;
        }
    }
    Ok(())
}

/// Whether `value` fits `field`. Image and claim values are not accepted by
/// this build from any writer: no task stores an image yet, and a claim is
/// written only by the subject's presentation, which this build does not
/// serve.
pub fn check(field: &FieldDef, value: &Value) -> Result<(), Unfit> {
    match (field.kind, value) {
        (FieldType::Image, _) => {
            Err("this community cannot store images for directory cards yet".into())
        }
        (FieldType::Claim, _) => {
            Err("a verified value is written only by presenting a credential".into())
        }
        (FieldType::MultiEnum, Value::Array(items)) => check_list(field, items),
        (FieldType::Url, Value::Array(items)) if field.key == "links" => check_list(field, items),
        (_, Value::String(s)) if !(field.kind == FieldType::Url && field.key == "links") => {
            check_scalar(field, s)
        }
        _ => Err("not a value of this field's type".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::fields::base_fields;
    use serde_json::json;

    fn base(key: &str) -> FieldDef {
        base_fields().into_iter().find(|f| f.key == key).unwrap()
    }

    fn community(kind: FieldType, constraints: Value) -> FieldDef {
        let mut f = base("displayName");
        f.key = "org.example.f".into();
        f.base = false;
        f.kind = kind;
        f.constraints = Some(constraints);
        f
    }

    #[test]
    fn text_bounds_and_lines() {
        let name = base("displayName");
        assert!(check(&name, &json!("Carol")).is_ok());
        assert!(check(&name, &json!("x".repeat(65))).is_err());
        assert!(check(&name, &json!("a\nb")).is_err());
        assert!(check(&base("bio"), &json!("a\nb")).is_ok());
        assert!(check(&name, &json!(7)).is_err());
    }

    #[test]
    fn links_are_a_short_list_of_web_urls() {
        let links = base("links");
        assert!(check(&links, &json!(["https://example.com/carol"])).is_ok());
        assert!(check(&links, &json!("https://example.com")).is_err());
        assert!(check(&links, &json!(["javascript:alert(1)"])).is_err());
        assert!(
            check(
                &links,
                &json!(
                    (0..6)
                        .map(|i| format!("https://e.com/{i}"))
                        .collect::<Vec<_>>()
                )
            )
            .is_err()
        );
    }

    #[test]
    fn enums_take_only_their_options() {
        let f = community(
            FieldType::Enum,
            json!({ "options": [{ "value": "sydney", "label": "Sydney" }] }),
        );
        assert!(check(&f, &json!("sydney")).is_ok());
        assert!(check(&f, &json!("berlin")).is_err());
        let mut m = f.clone();
        m.kind = FieldType::MultiEnum;
        assert!(check(&m, &json!(["sydney"])).is_ok());
        assert!(check(&m, &json!(["sydney", "sydney"])).is_err());
    }

    #[test]
    fn patterns_dates_countries_and_dids() {
        let p = community(FieldType::Text, json!({ "pattern": "^[A-Z]{3}$" }));
        assert!(check(&p, &json!("ABC")).is_ok());
        assert!(check(&p, &json!("abc")).is_err());
        let d = community(FieldType::Date, json!({ "minDate": "2000-01-01" }));
        assert!(check(&d, &json!("2020-02-29")).is_ok());
        assert!(check(&d, &json!("1999-12-31")).is_err());
        assert!(check(&d, &json!("2020-13-01")).is_err());
        let c = community(FieldType::Country, json!({}));
        assert!(check(&c, &json!("AU")).is_ok());
        assert!(check(&c, &json!("au")).is_err());
        let did = community(FieldType::Did, json!({}));
        assert!(check(&did, &json!("did:example:carol")).is_ok());
        assert!(check(&did, &json!("carol")).is_err());
    }

    #[test]
    fn images_and_claims_are_not_accepted_here() {
        assert!(
            check(
                &base("avatar"),
                &json!({ "sha256": "0".repeat(64), "mediaType": "image/png" })
            )
            .is_err()
        );
    }
}
