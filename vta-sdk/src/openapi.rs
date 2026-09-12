//! OpenAPI schemas for published Trust Task types a service serves over REST
//! (feature `openapi`).
//!
//! A generated type is foreign to every crate that serves it, so `ToSchema`
//! cannot be derived on it — and a local struct describing it would be exactly
//! the hand-written copy the generated types exist to remove. The schema comes
//! from the specification instead. Each type below wraps one generated type
//! transparently — the JSON on the wire is the generated type's own — and
//! documents it by rendering the JSON Schema that type embeds as OpenAPI
//! components.
//!
//! A handler takes and returns `Json<Wrapper>`, and its `#[utoipa::path]` names
//! the wrapper as the body, so the document describes what the specification
//! publishes rather than what someone transcribed from it. A field of a local
//! admin type can point at one with `#[schema(value_type = …)]`.
//!
//! ## Component names
//!
//! The task's slug and version, then the definition:
//! `VtcVettingVettersListV0_1Payload`, `VtcVettingVettersListV0_1ListedVetter`.
//! Two specifications that each define a `VetterEvent` cannot collide, and a
//! reader can tell which specification a component came from.
//!
//! ## What the rendering carries
//!
//! Structure and bounds: types, members, `required`, `additionalProperties`,
//! `oneOf`/`anyOf`/`allOf`, `enum`/`const`, `format`, patterns, lengths, item
//! counts and numeric ranges. JSON Schema keywords utoipa's model has no field
//! for — `dependentSchemas`, `dependentRequired`, `not`, `propertyNames` — are
//! not rendered; a service enforces them at runtime through
//! [`crate::protocols::vetting::CheckShape`].
//!
//! ## Exposing another type
//!
//! Add a line to the [`spec_types!`] table: the wrapper's name, the generated
//! type, and — for a type that is a `$defs` entry of another type's schema rather
//! than a payload or response itself — the carrier and the definition's name.

use std::borrow::Cow;
use std::ops::{Deref, DerefMut};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::openapi::schema::{
    AdditionalProperties, AllOfBuilder, AnyOfBuilder, ArrayBuilder, ObjectBuilder, OneOfBuilder,
    Schema, SchemaFormat, SchemaType, Type,
};
use utoipa::openapi::{Ref, RefOr};

use crate::protocols::vetting::vetters;
use trust_tasks_rs::specs::vtc::join_requests::manifest;

/// Transparent wrappers documenting generated types, one per line.
macro_rules! spec_types {
    ($(
        $(#[$doc:meta])*
        $name:ident($ty:ty) $(in $carrier:ty as $definition:literal)?;
    )+) => {
        $(
            $(#[$doc])*
            #[derive(Debug, Clone, Serialize, Deserialize)]
            #[serde(transparent)]
            pub struct $name(pub $ty);

            impl $name {
                /// The wrapped value.
                pub fn into_inner(self) -> $ty {
                    self.0
                }
            }

            impl From<$ty> for $name {
                fn from(value: $ty) -> Self {
                    Self(value)
                }
            }

            impl Deref for $name {
                type Target = $ty;
                fn deref(&self) -> &$ty {
                    &self.0
                }
            }

            impl DerefMut for $name {
                fn deref_mut(&mut self) -> &mut $ty {
                    &mut self.0
                }
            }

            impl utoipa::PartialSchema for $name {
                fn schema() -> RefOr<Schema> {
                    spec_types!(@rendered $ty $(, $carrier, $definition)?).schema
                }
            }

            impl utoipa::ToSchema for $name {
                fn name() -> Cow<'static, str> {
                    Cow::Owned(spec_types!(@rendered $ty $(, $carrier, $definition)?).name)
                }

                fn schemas(schemas: &mut Vec<(String, RefOr<Schema>)>) {
                    schemas.extend(
                        spec_types!(@rendered $ty $(, $carrier, $definition)?).definitions,
                    );
                }
            }
        )+
    };
    (@rendered $ty:ty) => {
        rendered::<$ty>(None)
    };
    (@rendered $ty:ty, $carrier:ty, $definition:literal) => {
        rendered::<$carrier>(Some($definition))
    };
}

spec_types! {
    /// `vtc/vetting/vetters/grant/0.1` payload.
    VetterGrant01Payload(vetters::grant::v0_1::Payload);
    /// `vtc/vetting/vetters/grant/0.1#response`.
    VetterGrant01Response(vetters::grant::v0_1::Response);
    /// `vtc/vetting/vetters/list/0.1` payload.
    VetterList01Payload(vetters::list::v0_1::Payload);
    /// `vtc/vetting/vetters/list/0.1#response`.
    VetterList01Response(vetters::list::v0_1::Response);
    /// `vtc/vetting/vetters/resend/0.1#response`.
    VetterResend01Response(vetters::resend::v0_1::Response);
    /// `vtc/vetting/vetters/profile/0.1`'s `VettingMethod`.
    VetterProfile01VettingMethod(vetters::profile::v0_1::VettingMethod)
        in vetters::profile::v0_1::Payload as "VettingMethod";
    /// `vtc/join-requests/manifest/0.1#response`.
    JoinManifest01Response(manifest::v0_1::Response);
    /// `vtc/join-requests/manifest/0.2#response`.
    JoinManifest02Response(manifest::v0_2::Response);
    /// `vtc/join-requests/manifest/0.2`'s `VettingRequirements`.
    JoinManifest02VettingRequirements(manifest::v0_2::VettingRequirements)
        in manifest::v0_2::Response as "VettingRequirements";
    /// `vtc/join-requests/manifest/0.2`'s `CommunityBranding` — also the body of a
    /// VTC's `GET`/`PUT /v1/community/branding`.
    JoinManifest02CommunityBranding(manifest::v0_2::CommunityBranding)
        in manifest::v0_2::Response as "CommunityBranding";
}

/// One type's component, and every other definition of its schema, which the
/// component may refer to.
struct Rendered {
    name: String,
    schema: RefOr<Schema>,
    definitions: Vec<(String, RefOr<Schema>)>,
}

/// Render the type `definition` names in `C`'s embedded schema — or, when it
/// names none, `C` itself.
fn rendered<C: trust_tasks_rs::Payload>(definition: Option<&str>) -> Rendered {
    let prefix = component_prefix(C::TYPE_URI);
    let schema: Value = C::PAYLOAD_SCHEMA
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(Value::Bool(true));
    let definitions = schema
        .get("$defs")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    // A named definition; else the definition a response schema's root refers
    // to; else the root itself, which is a payload.
    let own = definition.map(str::to_string).or_else(|| {
        schema
            .get("$ref")
            .and_then(Value::as_str)
            .and_then(|r| r.strip_prefix("#/$defs/"))
            .map(str::to_string)
    });
    let (name, node) = match &own {
        Some(definition) => (
            format!("{prefix}{definition}"),
            definitions
                .get(definition)
                .cloned()
                .unwrap_or(Value::Bool(true)),
        ),
        None => (format!("{prefix}Payload"), schema.clone()),
    };

    Rendered {
        name,
        schema: convert(&node, &prefix),
        definitions: definitions
            .iter()
            .filter(|(definition, _)| own.as_deref() != Some(definition.as_str()))
            .map(|(definition, node)| (format!("{prefix}{definition}"), convert(node, &prefix)))
            .collect(),
    }
}

/// `https://trusttasks.org/spec/vtc/join-requests/manifest/0.2#response` →
/// `VtcJoinRequestsManifestV0_2`.
fn component_prefix(type_uri: &str) -> String {
    let path = type_uri.split('#').next().unwrap_or(type_uri);
    let path = path.split_once("/spec/").map_or(path, |(_, p)| p);
    let mut segments: Vec<&str> = path.split('/').collect();
    let version = segments.pop().unwrap_or_default();
    let mut out = String::new();
    for word in segments.iter().flat_map(|s| s.split('-')) {
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    out.push('V');
    out.push_str(&version.replace('.', "_"));
    out
}

fn convert(node: &Value, prefix: &str) -> RefOr<Schema> {
    let Some(obj) = node.as_object() else {
        // `true`: anything.
        return RefOr::T(Schema::Object(
            ObjectBuilder::new()
                .schema_type(SchemaType::AnyValue)
                .build(),
        ));
    };
    let description = obj.get("description").and_then(Value::as_str);

    if let Some(target) = obj.get("$ref").and_then(Value::as_str) {
        let name = target
            .strip_prefix("#/$defs/")
            .map_or_else(|| target.to_string(), |d| format!("{prefix}{d}"));
        return RefOr::Ref(Ref::from_schema_name(name));
    }
    if let Some(items) = obj.get("oneOf").and_then(Value::as_array) {
        let builder = items
            .iter()
            .fold(OneOfBuilder::new().description(description), |b, item| {
                b.item(convert(item, prefix))
            });
        return RefOr::T(Schema::OneOf(builder.build()));
    }
    if let Some(items) = obj.get("anyOf").and_then(Value::as_array) {
        let builder = items
            .iter()
            .fold(AnyOfBuilder::new().description(description), |b, item| {
                b.item(convert(item, prefix))
            });
        return RefOr::T(Schema::AnyOf(builder.build()));
    }
    if let Some(items) = obj.get("allOf").and_then(Value::as_array) {
        let builder = items
            .iter()
            .fold(AllOfBuilder::new().description(description), |b, item| {
                b.item(convert(item, prefix))
            });
        return RefOr::T(Schema::AllOf(builder.build()));
    }

    match obj.get("type").and_then(Value::as_str) {
        Some("object") => object(obj, description, prefix),
        Some("array") => array(obj, description, prefix),
        None if obj.contains_key("properties") => object(obj, description, prefix),
        Some("string") => scalar(obj, description, SchemaType::Type(Type::String)),
        Some("integer") => scalar(obj, description, SchemaType::Type(Type::Integer)),
        Some("number") => scalar(obj, description, SchemaType::Type(Type::Number)),
        Some("boolean") => scalar(obj, description, SchemaType::Type(Type::Boolean)),
        _ => scalar(obj, description, SchemaType::AnyValue),
    }
}

fn object(obj: &Map<String, Value>, description: Option<&str>, prefix: &str) -> RefOr<Schema> {
    let mut b = ObjectBuilder::new()
        .schema_type(SchemaType::Type(Type::Object))
        .description(description);
    if let Some(properties) = obj.get("properties").and_then(Value::as_object) {
        for (name, property) in properties {
            b = b.property(name, convert(property, prefix));
        }
    }
    for required in obj
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        b = b.required(required);
    }
    match obj.get("additionalProperties") {
        Some(Value::Bool(allowed)) => {
            b = b.additional_properties(Some(AdditionalProperties::<Schema>::FreeForm(*allowed)));
        }
        Some(schema @ Value::Object(_)) => {
            b = b.additional_properties(Some(AdditionalProperties::RefOr(convert(schema, prefix))));
        }
        _ => {}
    }
    b = b.min_properties(count(obj, "minProperties"));
    RefOr::T(Schema::Object(b.build()))
}

fn array(obj: &Map<String, Value>, description: Option<&str>, prefix: &str) -> RefOr<Schema> {
    let mut b = ArrayBuilder::new().description(description);
    if let Some(items) = obj.get("items") {
        b = b.items(convert(items, prefix));
    }
    b = b
        .min_items(count(obj, "minItems"))
        .max_items(count(obj, "maxItems"))
        .unique_items(obj.get("uniqueItems") == Some(&Value::Bool(true)));
    RefOr::T(Schema::Array(b.build()))
}

fn scalar(
    obj: &Map<String, Value>,
    description: Option<&str>,
    schema_type: SchemaType,
) -> RefOr<Schema> {
    let mut b = ObjectBuilder::new()
        .schema_type(schema_type)
        .description(description)
        .format(
            obj.get("format")
                .and_then(Value::as_str)
                .map(|f| SchemaFormat::Custom(f.to_string())),
        )
        .pattern(obj.get("pattern").and_then(Value::as_str))
        .min_length(count(obj, "minLength"))
        .max_length(count(obj, "maxLength"))
        .minimum(number(obj, "minimum"))
        .maximum(number(obj, "maximum"));
    if let Some(values) = obj.get("enum").and_then(Value::as_array) {
        b = b.enum_values(Some(values.iter().cloned()));
    } else if let Some(value) = obj.get("const") {
        b = b.enum_values(Some([value.clone()]));
    }
    RefOr::T(Schema::Object(b.build()))
}

fn count(obj: &Map<String, Value>, keyword: &str) -> Option<usize> {
    obj.get(keyword)
        .and_then(Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
}

fn number(obj: &Map<String, Value>, keyword: &str) -> Option<utoipa::Number> {
    let value = obj.get(keyword)?;
    value
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .map(utoipa::Number::UInt)
        .or_else(|| {
            value
                .as_i64()
                .and_then(|n| isize::try_from(n).ok())
                .map(utoipa::Number::Int)
        })
        .or_else(|| value.as_f64().map(utoipa::Number::Float))
}

#[cfg(test)]
mod tests {
    use super::*;
    use utoipa::{PartialSchema, ToSchema};

    fn every_ref(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                if let Some(Value::String(r)) = map.get("$ref") {
                    out.push(r.clone());
                }
                map.values().for_each(|v| every_ref(v, out));
            }
            Value::Array(items) => items.iter().for_each(|v| every_ref(v, out)),
            _ => {}
        }
    }

    #[test]
    fn components_are_named_for_their_specification() {
        assert_eq!(
            component_prefix("https://trusttasks.org/spec/vtc/join-requests/manifest/0.2#response"),
            "VtcJoinRequestsManifestV0_2"
        );
        assert_eq!(
            VetterList01Response::name(),
            "VtcVettingVettersListV0_1Response"
        );
        assert_eq!(
            VetterGrant01Payload::name(),
            "VtcVettingVettersGrantV0_1Payload"
        );
        assert_eq!(
            JoinManifest02VettingRequirements::name(),
            "VtcJoinRequestsManifestV0_2VettingRequirements"
        );
    }

    /// Every reference resolves to a component the type brings with it, so a
    /// document built from these has no dangling `$ref` and no JSON Schema
    /// `$defs` pointer OpenAPI cannot follow.
    #[test]
    fn every_reference_resolves_to_a_component_the_type_brings() {
        fn check<T: ToSchema>() {
            let mut components = vec![(T::name().into_owned(), <T as PartialSchema>::schema())];
            T::schemas(&mut components);
            let names: Vec<&str> = components.iter().map(|(n, _)| n.as_str()).collect();
            let mut refs = Vec::new();
            for (_, schema) in &components {
                every_ref(&serde_json::to_value(schema).unwrap(), &mut refs);
            }
            assert!(components.len() > 1 || refs.is_empty());
            for r in refs {
                let name = r
                    .strip_prefix("#/components/schemas/")
                    .unwrap_or_else(|| panic!("{r} is not a component reference"));
                assert!(names.contains(&name), "{r} dangles");
            }
        }
        check::<VetterGrant01Payload>();
        check::<VetterGrant01Response>();
        check::<VetterList01Payload>();
        check::<VetterList01Response>();
        check::<VetterResend01Response>();
        check::<VetterProfile01VettingMethod>();
        check::<JoinManifest01Response>();
        check::<JoinManifest02Response>();
        check::<JoinManifest02VettingRequirements>();
        check::<JoinManifest02CommunityBranding>();
    }

    #[test]
    fn a_rendered_schema_keeps_the_specifications_bounds() {
        let mut components = Vec::new();
        VetterList01Response::schemas(&mut components);
        let listed = components
            .iter()
            .find(|(n, _)| n == "VtcVettingVettersListV0_1ListedVetter")
            .map(|(_, s)| serde_json::to_value(s).unwrap())
            .expect("ListedVetter is a component");
        assert_eq!(listed["additionalProperties"], false);
        assert!(
            listed["required"]
                .as_array()
                .unwrap()
                .contains(&Value::from("vetterDid"))
        );
        assert_eq!(listed["properties"]["languages"]["maxItems"], 16);
        assert_eq!(listed["properties"]["vetterDid"]["pattern"], "^did:");

        let root = serde_json::to_value(VetterGrant01Payload::schema()).unwrap();
        assert_eq!(root["properties"]["validitySeconds"]["minimum"], 86_400);
        assert_eq!(root["required"], serde_json::json!(["memberDid"]));
    }

    #[test]
    fn a_wrapper_is_invisible_on_the_wire() {
        let json = serde_json::json!({ "memberDid": "did:key:zCarol" });
        let wrapped: VetterGrant01Payload = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(wrapped.member_did.as_str(), "did:key:zCarol");
        assert_eq!(serde_json::to_value(&wrapped).unwrap(), json);
    }
}
