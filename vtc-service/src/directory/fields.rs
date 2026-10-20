//! The directory's field schema: the base fields every community has, the
//! fields its administrators define, and the rules for changing either
//! (`vtc/directory/fields/{list,define,update,retire}/0.1`).
//!
//! Base fields live in code ([`base_fields`]). A community changes one by
//! writing a full definition under its key, which then wins; it never defines
//! one. Community fields are stored the same way, under a reverse-DNS key, and
//! are never deleted: a retired field keeps its row, so its key stays reserved
//! for ever (VTI-DIR-015).

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::model::{Audience, FieldDef, FieldSource, FieldState, FieldType};

/// How many community fields may be `active` at once (VTI-DIR-016).
pub const MAX_ACTIVE_COMMUNITY_FIELDS: usize = 64;

const FIELD_PREFIX: &str = "field:";

fn field_key(key: &str) -> String {
    format!("{FIELD_PREFIX}{key}")
}

/// The base keys a member writes.
pub const MEMBER_BASE_KEYS: [&str; 6] = [
    "displayName",
    "nickname",
    "avatar",
    "pronouns",
    "bio",
    "links",
];

/// The derived base keys: read from the community's own records when a
/// projection is made, never stored on a card (VTI-DIR-011).
pub const DERIVED_KEYS: [&str; 4] = ["role", "joinedAt", "did", "personhood"];

/// The one derived field whose visibility a member may choose: their own DID,
/// which only they may decide to show (VTI-DIR-042).
pub const MEMBER_CHOOSABLE_DERIVED: &str = "did";

#[allow(clippy::too_many_arguments)]
fn base(
    key: &str,
    label: &str,
    kind: FieldType,
    source: FieldSource,
    js: Option<&str>,
    constraints: Option<Value>,
    ceiling: Audience,
    default_visibility: Audience,
    searchable: bool,
    order: i64,
) -> FieldDef {
    FieldDef {
        key: key.into(),
        label: label.into(),
        description: None,
        kind,
        constraints,
        source,
        base: true,
        js_contact_path: js.map(str::to_string),
        // A name is what makes an entry useful to browse; nothing else is
        // needed to be listed.
        required: key == "displayName",
        ceiling,
        default_visibility,
        searchable,
        facet: false,
        order,
        state: FieldState::Active,
        retired_at: None,
        purge_after: None,
        updated_at: None,
    }
}

/// The base fields, as this build ships them (design §4.1).
///
/// Defaults follow VTI-DIR-041 and VTI-DIR-042: a new card shows its display
/// name and community role to members and every other value to
/// administrators only; nothing reaches `public` and the DID never leaves the
/// administrators until its member chooses.
pub fn base_fields() -> Vec<FieldDef> {
    use Audience::*;
    use FieldSource::*;
    use FieldType as T;
    vec![
        base(
            "displayName",
            "Name",
            T::Text,
            Member,
            Some("name.full"),
            Some(json!({ "maxLength": 64 })),
            Public,
            Members,
            true,
            0,
        ),
        base(
            "nickname",
            "Nickname",
            T::Text,
            Member,
            Some("nicknames"),
            Some(json!({ "maxLength": 32 })),
            Public,
            Admins,
            true,
            10,
        ),
        base(
            "avatar",
            "Picture",
            T::Image,
            Member,
            Some("media"),
            None,
            Public,
            Admins,
            false,
            20,
        ),
        base(
            "pronouns",
            "Pronouns",
            T::Text,
            Member,
            Some("speakToAs.pronouns"),
            Some(json!({ "maxLength": 32 })),
            Public,
            Admins,
            false,
            30,
        ),
        base(
            "bio",
            "About",
            T::LongText,
            Member,
            Some("notes"),
            Some(json!({ "maxLength": 500 })),
            Public,
            Admins,
            false,
            40,
        ),
        base(
            "links",
            "Links",
            T::Url,
            Member,
            Some("links"),
            Some(json!({ "maxItems": 5, "maxLength": 500 })),
            Public,
            Admins,
            false,
            50,
        ),
        base(
            "role",
            "Role",
            T::Text,
            Derived,
            None,
            None,
            Members,
            Members,
            false,
            80,
        ),
        base(
            "joinedAt",
            "Joined",
            T::Date,
            Derived,
            None,
            None,
            Members,
            Admins,
            false,
            85,
        ),
        base(
            "did",
            "DID",
            T::Did,
            Derived,
            None,
            None,
            Members,
            Admins,
            false,
            90,
        ),
        base(
            "personhood",
            "Personhood",
            T::Text,
            Derived,
            None,
            None,
            Members,
            Admins,
            false,
            95,
        ),
    ]
}

/// Whether `key` names a base field.
pub fn is_base_key(key: &str) -> bool {
    !key.contains('.')
}

/// The community's whole schema, base and defined, every state, in `order`
/// (then key, so the order is total).
pub async fn schema(ks: &KeyspaceHandle) -> Result<Vec<FieldDef>, AppError> {
    let mut by_key: BTreeMap<String, FieldDef> = base_fields()
        .into_iter()
        .map(|f| (f.key.clone(), f))
        .collect();
    for (_, raw) in ks.prefix_iter_raw(FIELD_PREFIX.as_bytes().to_vec()).await? {
        let f: FieldDef = serde_json::from_slice(&raw).map_err(|e| {
            AppError::Internal(format!("stored directory field is unreadable: {e}"))
        })?;
        // A stored base row may only ever change a base field; a base key
        // that is not one of this build's is ignored rather than invented.
        if f.base && !by_key.contains_key(&f.key) {
            continue;
        }
        by_key.insert(f.key.clone(), f);
    }
    let mut out: Vec<FieldDef> = by_key.into_values().collect();
    out.sort_by(|a, b| a.order.cmp(&b.order).then_with(|| a.key.cmp(&b.key)));
    Ok(out)
}

/// One field by key, base or defined, in whatever state.
pub async fn get(ks: &KeyspaceHandle, key: &str) -> Result<Option<FieldDef>, AppError> {
    if let Some(raw) = ks.get_raw(field_key(key).into_bytes()).await? {
        let f: FieldDef = serde_json::from_slice(&raw).map_err(|e| {
            AppError::Internal(format!("stored directory field is unreadable: {e}"))
        })?;
        return Ok(Some(f));
    }
    Ok(base_fields().into_iter().find(|f| f.key == key))
}

async fn put(ks: &KeyspaceHandle, f: &FieldDef) -> Result<(), AppError> {
    ks.insert(field_key(&f.key).into_bytes(), f).await?;
    super::changed();
    Ok(())
}

/// Why a field write was refused — one variant per declared error code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldError {
    FieldExists,
    ReservedKey,
    AboveCeiling,
    ValueInvalid { field: String, reason: String },
    TooManyFields,
    FieldUnknown,
    FieldRetired,
    BaseField,
}

fn invalid(field: &str, reason: impl Into<String>) -> FieldError {
    FieldError::ValueInvalid {
        field: field.to_string(),
        reason: reason.into(),
    }
}

/// Check `constraints` against `kind` (define item 3, update item 3): a
/// member that does not apply to the type is refused, not ignored.
pub fn check_constraints(
    key: &str,
    kind: FieldType,
    source: FieldSource,
    constraints: Option<&Value>,
) -> Result<(), FieldError> {
    let Some(c) = constraints else {
        if kind == FieldType::Claim {
            return Err(invalid(key, "a claim field names the claim it accepts"));
        }
        if matches!(kind, FieldType::Enum | FieldType::MultiEnum) {
            return Err(invalid(key, "an enum field lists its options"));
        }
        return Ok(());
    };
    let obj = c
        .as_object()
        .ok_or_else(|| invalid(key, "constraints are an object"))?;
    let textual = matches!(
        kind,
        FieldType::Text
            | FieldType::LongText
            | FieldType::Url
            | FieldType::Email
            | FieldType::Phone
    );
    for member in obj.keys() {
        let fits = match member.as_str() {
            "maxLength" | "minLength" => textual,
            "pattern" => textual,
            "options" => matches!(kind, FieldType::Enum | FieldType::MultiEnum),
            "maxItems" => {
                kind == FieldType::MultiEnum || (kind == FieldType::Url && key == "links")
            }
            "minDate" | "maxDate" => kind == FieldType::Date,
            "claim" => kind == FieldType::Claim,
            _ => false,
        };
        if !fits {
            return Err(invalid(
                key,
                format!("`{member}` does not apply to a field of this type"),
            ));
        }
    }
    if let (Some(min), Some(max)) = (
        obj.get("minLength").and_then(Value::as_u64),
        obj.get("maxLength").and_then(Value::as_u64),
    ) && min > max
    {
        return Err(invalid(key, "minLength is greater than maxLength"));
    }
    if let Some(p) = obj.get("pattern").and_then(Value::as_str)
        && regress::Regex::new(p).is_err()
    {
        return Err(invalid(key, "pattern is not a regular expression"));
    }
    if matches!(kind, FieldType::Enum | FieldType::MultiEnum) {
        let options = obj
            .get("options")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid(key, "an enum field lists its options"))?;
        let mut seen = std::collections::BTreeSet::new();
        for o in options {
            let v = o.get("value").and_then(Value::as_str).unwrap_or_default();
            if !seen.insert(v) {
                return Err(invalid(key, format!("option `{v}` is listed twice")));
            }
        }
    }
    if kind == FieldType::Claim && obj.get("claim").is_none() {
        return Err(invalid(key, "a claim field names the claim it accepts"));
    }
    if kind == FieldType::Claim && source != FieldSource::Credential {
        return Err(invalid(key, "a claim field is credential-sourced"));
    }
    Ok(())
}

/// Checks every definition must pass, whoever wrote it.
fn check_definition(f: &FieldDef) -> Result<(), FieldError> {
    if !f.default_visibility.within(f.ceiling) {
        return Err(FieldError::AboveCeiling);
    }
    if f.facet && !f.kind.may_be_facet() {
        return Err(invalid(
            &f.key,
            "only enum, multiEnum and country fields may be facets",
        ));
    }
    if f.kind == FieldType::Claim && f.source != FieldSource::Credential {
        return Err(invalid(&f.key, "a claim field is credential-sourced"));
    }
    if f.source == FieldSource::Credential && f.kind != FieldType::Claim {
        return Err(invalid(
            &f.key,
            "a credential-sourced field is a claim field",
        ));
    }
    if f.source == FieldSource::Derived && (f.searchable || f.facet) {
        return Err(invalid(
            &f.key,
            "a derived field is never searched or counted by members",
        ));
    }
    if f.searchable && !f.kind.is_textual() {
        return Err(invalid(
            &f.key,
            "only a text-valued field may be searchable",
        ));
    }
    check_constraints(&f.key, f.kind, f.source, f.constraints.as_ref())
}

/// `fields/define`: a new community field, stored `active`.
pub async fn define(
    ks: &KeyspaceHandle,
    input: &Value,
    now: DateTime<Utc>,
) -> Result<FieldDef, FieldError> {
    let s = |k: &str| input.get(k).and_then(Value::as_str);
    let key = s("key").unwrap_or_default().to_string();
    if is_base_key(&key) {
        return Err(FieldError::ReservedKey);
    }
    let parse = |v: Option<&Value>| -> Option<Value> { v.cloned() };
    let kind: FieldType = serde_json::from_value(input["type"].clone())
        .map_err(|_| invalid(&key, "unknown field type"))?;
    let source: FieldSource = serde_json::from_value(input["source"].clone())
        .map_err(|_| invalid(&key, "unknown field source"))?;
    let ceiling = s("ceiling")
        .and_then(Audience::parse)
        .ok_or_else(|| invalid(&key, "unknown ceiling"))?;
    let default_visibility = s("defaultVisibility")
        .and_then(Audience::parse)
        .ok_or_else(|| invalid(&key, "unknown default visibility"))?;
    let f = FieldDef {
        key: key.clone(),
        label: s("label").unwrap_or_default().to_string(),
        description: s("description").map(str::to_string),
        kind,
        constraints: parse(input.get("constraints")),
        source,
        base: false,
        js_contact_path: None,
        required: input
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        ceiling,
        default_visibility,
        searchable: input
            .get("searchable")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        facet: input.get("facet").and_then(Value::as_bool).unwrap_or(false),
        order: input.get("order").and_then(Value::as_i64).unwrap_or(100),
        state: FieldState::Active,
        retired_at: None,
        purge_after: None,
        updated_at: Some(now),
    };
    check_definition(&f)?;

    // Under the write lock: two defines of one key must not both pass the
    // existence check.
    let _guard = super::WRITE_LOCK.lock().await;
    if ks
        .get_raw(field_key(&key).into_bytes())
        .await
        .map_err(|e| invalid(&key, e.to_string()))?
        .is_some()
    {
        return Err(FieldError::FieldExists);
    }
    let active = schema(ks)
        .await
        .map_err(|e| invalid(&key, e.to_string()))?
        .iter()
        .filter(|d| !d.base && d.state == FieldState::Active)
        .count();
    if active >= MAX_ACTIVE_COMMUNITY_FIELDS {
        return Err(FieldError::TooManyFields);
    }
    put(ks, &f)
        .await
        .map_err(|e| invalid(&key, e.to_string()))?;
    Ok(f)
}

/// What an update changes, and whether any of it widens (update §"Widening is
/// held, not refused"): after it, some viewer could see or find what they
/// could not before.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldChange {
    pub before: FieldDef,
    pub after: FieldDef,
}

impl FieldChange {
    pub fn widens(&self) -> bool {
        let (b, a) = (&self.before, &self.after);
        a.ceiling.reaches_beyond(b.ceiling)
            || a.default_visibility.reaches_beyond(b.default_visibility)
            || (a.searchable && !b.searchable)
            || (a.facet && !b.facet)
            // Re-enabling a field shows the values it has been holding.
            || (a.state == FieldState::Active && b.state != FieldState::Active)
            // Dropping a requirement lists entries that were not listed.
            || (!a.required && b.required)
    }

    pub fn changes_nothing(&self) -> bool {
        let mut a = self.after.clone();
        a.updated_at = self.before.updated_at;
        a == self.before
    }
}

/// `fields/update`: the definition as it would be after `payload`, checked,
/// not stored. [`store_update`] writes it.
pub async fn plan_update(
    ks: &KeyspaceHandle,
    payload: &Value,
    now: DateTime<Utc>,
) -> Result<FieldChange, FieldError> {
    let key = payload
        .get("key")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let before = get(ks, &key)
        .await
        .map_err(|e| invalid(&key, e.to_string()))?
        .ok_or(FieldError::FieldUnknown)?;
    if before.state == FieldState::Retired {
        return Err(FieldError::FieldRetired);
    }
    let mut after = before.clone();
    let s = |k: &str| payload.get(k).and_then(Value::as_str);
    if let Some(l) = s("label") {
        after.label = l.to_string();
    }
    if let Some(d) = s("description") {
        after.description = Some(d.to_string());
    }
    if let Some(c) = payload.get("constraints") {
        after.constraints = Some(c.clone());
    }
    if let Some(c) = s("ceiling") {
        after.ceiling = Audience::parse(c).ok_or_else(|| invalid(&key, "unknown ceiling"))?;
    }
    if let Some(v) = s("defaultVisibility") {
        after.default_visibility =
            Audience::parse(v).ok_or_else(|| invalid(&key, "unknown default visibility"))?;
    }
    for (member, slot) in [
        ("required", &mut after.required),
        ("searchable", &mut after.searchable),
        ("facet", &mut after.facet),
    ] {
        if let Some(b) = payload.get(member).and_then(Value::as_bool) {
            *slot = b;
        }
    }
    if let Some(o) = payload.get("order").and_then(Value::as_i64) {
        after.order = o;
    }
    if let Some(enabled) = payload.get("enabled").and_then(Value::as_bool) {
        if !before.base {
            return Err(invalid(&key, "`enabled` applies to base fields only"));
        }
        after.state = if enabled {
            FieldState::Active
        } else {
            FieldState::Disabled
        };
    }
    after.updated_at = Some(now);
    check_definition(&after)?;
    Ok(FieldChange { before, after })
}

/// Store a planned update, provided the field is still as it was planned
/// from. `false` when it moved in the meantime: plan again.
pub async fn store_update(ks: &KeyspaceHandle, change: &FieldChange) -> Result<bool, AppError> {
    let _guard = super::WRITE_LOCK.lock().await;
    let current = get(ks, &change.after.key).await?;
    let mut was = change.before.clone();
    let mut now_is = current.clone();
    // `updated_at` is when, not what.
    was.updated_at = None;
    if let Some(n) = now_is.as_mut() {
        n.updated_at = None;
    }
    if now_is.as_ref() != Some(&was) {
        return Ok(false);
    }
    put(ks, &change.after).await?;
    Ok(true)
}

/// `fields/retire`: hide the field at once and schedule its values' purge.
pub async fn retire(
    ks: &KeyspaceHandle,
    key: &str,
    retention_days: u32,
    now: DateTime<Utc>,
) -> Result<FieldDef, FieldError> {
    let _guard = super::WRITE_LOCK.lock().await;
    let mut f = get(ks, key)
        .await
        .map_err(|e| invalid(key, e.to_string()))?
        .ok_or(FieldError::FieldUnknown)?;
    if f.base {
        return Err(FieldError::BaseField);
    }
    if f.state == FieldState::Retired {
        return Err(FieldError::FieldRetired);
    }
    f.state = FieldState::Retired;
    f.retired_at = Some(now);
    f.purge_after = Some(now + Duration::days(i64::from(retention_days)));
    f.updated_at = Some(now);
    put(ks, &f).await.map_err(|e| invalid(key, e.to_string()))?;
    Ok(f)
}

/// Retired fields whose purge is due at `now`, not yet purged.
pub async fn due_for_purge(
    ks: &KeyspaceHandle,
    now: DateTime<Utc>,
) -> Result<Vec<String>, AppError> {
    Ok(schema(ks)
        .await?
        .into_iter()
        .filter(|f| f.state == FieldState::Retired && f.purge_after.is_some_and(|p| p <= now))
        .map(|f| f.key)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(key: &str) -> Value {
        json!({
            "key": key, "label": "Employer", "type": "text", "source": "member",
            "ceiling": "members", "defaultVisibility": "members", "searchable": true,
        })
    }

    async fn ks() -> KeyspaceHandle {
        super::super::tests::scratch().await
    }

    #[test]
    fn base_defaults_show_only_name_and_role_to_members() {
        // VTI-DIR-041 / VTI-DIR-042.
        for f in base_fields() {
            let to_members = f.default_visibility == Audience::Members;
            assert_eq!(
                to_members,
                f.key == "displayName" || f.key == "role",
                "{}",
                f.key
            );
            assert!(f.default_visibility.within(f.ceiling), "{}", f.key);
            assert_ne!(f.default_visibility, Audience::Public, "{}", f.key);
        }
        let did = base_fields().into_iter().find(|f| f.key == "did").unwrap();
        assert_eq!(did.default_visibility, Audience::Admins);
    }

    #[tokio::test]
    async fn vti_dir_015_a_key_is_never_reused() {
        let ks = ks().await;
        let now = Utc::now();
        define(&ks, &input("org.example.employer"), now)
            .await
            .unwrap();
        assert_eq!(
            define(&ks, &input("org.example.employer"), now).await,
            Err(FieldError::FieldExists)
        );
        retire(&ks, "org.example.employer", 30, now).await.unwrap();
        assert_eq!(
            define(&ks, &input("org.example.employer"), now).await,
            Err(FieldError::FieldExists),
            "a retired key stays reserved"
        );
        assert_eq!(
            retire(&ks, "org.example.employer", 30, now).await,
            Err(FieldError::FieldRetired)
        );
    }

    #[tokio::test]
    async fn base_keys_are_reserved_and_not_retired() {
        let ks = ks().await;
        assert_eq!(
            define(&ks, &input("employer"), Utc::now()).await,
            Err(FieldError::ReservedKey)
        );
        assert_eq!(
            retire(&ks, "bio", 30, Utc::now()).await,
            Err(FieldError::BaseField)
        );
    }

    #[tokio::test]
    async fn a_default_wider_than_its_ceiling_is_refused() {
        let ks = ks().await;
        let mut i = input("org.example.a");
        i["defaultVisibility"] = json!("public");
        assert_eq!(
            define(&ks, &i, Utc::now()).await,
            Err(FieldError::AboveCeiling)
        );
        // groups and connections are not ordered: neither is within the other.
        i["ceiling"] = json!("connections");
        i["defaultVisibility"] = json!("groups");
        assert_eq!(
            define(&ks, &i, Utc::now()).await,
            Err(FieldError::AboveCeiling)
        );
    }

    #[tokio::test]
    async fn constraints_that_do_not_fit_the_type_are_refused() {
        let ks = ks().await;
        let mut i = input("org.example.a");
        i["constraints"] = json!({ "options": [{ "value": "a", "label": "A" }] });
        assert!(matches!(
            define(&ks, &i, Utc::now()).await,
            Err(FieldError::ValueInvalid { .. })
        ));
        let mut i = input("org.example.b");
        i["facet"] = json!(true);
        assert!(matches!(
            define(&ks, &i, Utc::now()).await,
            Err(FieldError::ValueInvalid { .. })
        ));
        let mut i = input("org.example.c");
        i["type"] = json!("claim");
        i["constraints"] = json!({ "claim": { "credentialType": "X", "claimPath": "/a" } });
        assert!(
            matches!(
                define(&ks, &i, Utc::now()).await,
                Err(FieldError::ValueInvalid { .. })
            ),
            "a claim field must be credential-sourced"
        );
        i["source"] = json!("credential");
        i["searchable"] = json!(false);
        define(&ks, &i, Utc::now()).await.unwrap();
    }

    #[tokio::test]
    async fn widening_and_narrowing_are_told_apart() {
        let ks = ks().await;
        let now = Utc::now();
        let narrow = plan_update(&ks, &json!({ "key": "bio", "ceiling": "members" }), now)
            .await
            .unwrap();
        assert!(!narrow.widens());
        let wide = plan_update(
            &ks,
            &json!({ "key": "bio", "defaultVisibility": "members" }),
            now,
        )
        .await
        .unwrap();
        assert!(wide.widens());
        let both = plan_update(
            &ks,
            &json!({ "key": "nickname", "ceiling": "members", "searchable": false, "required": false }),
            now,
        )
        .await
        .unwrap();
        assert!(!both.widens(), "nickname was not required");
        let disable = plan_update(&ks, &json!({ "key": "bio", "enabled": false }), now)
            .await
            .unwrap();
        assert!(!disable.widens());
        assert!(store_update(&ks, &disable).await.unwrap());
        let enable = plan_update(&ks, &json!({ "key": "bio", "enabled": true }), now)
            .await
            .unwrap();
        assert!(enable.widens(), "re-enabling shows held values again");
    }

    #[tokio::test]
    async fn enabled_is_for_base_fields_only() {
        let ks = ks().await;
        let now = Utc::now();
        define(&ks, &input("org.example.a"), now).await.unwrap();
        assert!(matches!(
            plan_update(
                &ks,
                &json!({ "key": "org.example.a", "enabled": false }),
                now
            )
            .await,
            Err(FieldError::ValueInvalid { .. })
        ));
        assert_eq!(
            plan_update(&ks, &json!({ "key": "org.example.zzz" }), now).await,
            Err(FieldError::FieldUnknown)
        );
    }
}
