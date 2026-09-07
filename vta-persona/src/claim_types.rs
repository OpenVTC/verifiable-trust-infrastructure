//! The claim-type registry, and the per-axis resolution its §4 makes normative.
//!
//! The table below is transcribed from
//! `specs/persona/_shared/0.1/claim-types.json` at **`registryVersion` 0.1**,
//! and the rules it is read by are `CLAIM-TYPES.md` §4 beside it. Both halves
//! are quoted rather than paraphrased where a paraphrase could drift.
//!
//! # Why the table is embedded
//!
//! Because there is nowhere yet to fetch it from. `CLAIM-TYPES.md` §6 leaves
//! `persona/claim-types/list` as an open question — "worth doing when the first
//! extension type ships, not before" — so no agent serves the table and no
//! client can learn one its build predates. Until that task exists, a copy is
//! the only way to have the table at all, and a copy that names its source and
//! its `registryVersion` is the only kind that can later be checked against it.
//!
//! Three columns of the source are deliberately **not** transcribed —
//! `valueType`, `minimumSet` and `oidc`. Nothing in this workspace reads them,
//! and a column carried without a reader is a column that goes stale without
//! anything failing.
//!
//! # Three axes, and they are not the same axis
//!
//! [`Sensitivity`] is how carefully a value is shown **to its own holder**.
//! [`ReleaseRequirement`] is what it takes to let the value **leave**.
//! [`MaskStyle`] is how it is drawn when it is shown at all — and is
//! independent of the other two: any style that is not [`MaskStyle::None`] is
//! masked on screen whatever its sensitivity, which is how `email.work` can be
//! worth hiding from the person behind you without being worth withholding
//! from every listing.
//!
//! Reading any one as a proxy for another produces a consumer that hides the
//! wrong things, so they resolve independently even though one lookup answers
//! all three.
//!
//! # What this module decides, and what it does not
//!
//! Only [`Sensitivity`] is acted on today, by
//! [`PersonaStore::list_attributes`](crate::PersonaStore::list_attributes),
//! which is the read-path control that makes the axis more than cosmetic.
//! Nothing consults [`ReleaseRequirement`]: `persona/disclosure/present` does
//! not yet demand a fresh authentication for a `stepUp` attribute, and a holder
//! **cannot** record a `release` override, precisely so that nothing here can
//! be mistaken for a gate that exists. `MaskStyle` is a renderer's business and
//! this crate draws nothing.
//!
//! They are resolved anyway because §4 is one rule over one table. The
//! alternative is a second copy of both, added when the disclosure gate lands,
//! which is how the two would come to disagree.

use serde::{Deserialize, Serialize};

use crate::model::Attribute;

/// How carefully a value is shown to its own holder.
///
/// `high` means the value is withheld from a listing that did not explicitly
/// ask for sensitive values — and, being withheld, masked when a consumer holds
/// it anyway. The withholding is the half that is not cosmetic: masking a value
/// already fetched defends a screen, and is no defence against a log, a crash
/// dump, or the memory of the process holding it.
///
/// Variants are declared **most protective first**, and [`Ord`] is derived from
/// that order, so "the more protective of two" is `min()` rather than a
/// hand-written table that can disagree with itself. [`crate::ProofRung`] is
/// ordered for the same reason and reads the same way.
///
/// The consequence worth stating, because the comparison looks backwards: for
/// two sensitivities `a < b` means *a is stricter than b*, not *a is less
/// sensitive*.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Sensitivity {
    High,
    Normal,
}

/// What it takes to let a value leave.
///
/// `stepUp` requires a fresh authentication bound to *that* preview rather than
/// to the session — without the binding, "each time" degrades into "once per
/// login", which is the failure the requirement exists to prevent.
///
/// Ordered most protective first, like [`Sensitivity`]. **Nothing enforces this
/// axis yet**; see the module documentation for why it is resolved regardless.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReleaseRequirement {
    StepUp,
    Consent,
}

/// How a value is drawn when it is shown.
///
/// A property of the *type*, because only the type knows which characters are
/// the recognisable ones: the last four of a card, the domain of an email
/// address, none of a display name. A mask applies to a rendering and never to
/// what is stored or sent, so this crate stores it and draws nothing.
///
/// Ordered most protective first, like the other two axes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MaskStyle {
    Full,
    Last2,
    Last4,
    EmailLocal,
    None,
}

/// The three axes as they resolve for one claim type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Axes {
    pub sensitivity: Sensitivity,
    pub release: ReleaseRequirement,
    pub mask: MaskStyle,
}

/// One row of the registry.
#[derive(Clone, Copy, Debug)]
struct Entry {
    token: &'static str,
    axes: Axes,
}

/// `defaults.unregistered` — what an axis resolves to when neither an exact
/// entry nor a registered family supplies it.
///
/// Deliberately the conservative answer. A vocabulary this registry has never
/// seen is exactly the one nobody has reasoned about, and an unknown value
/// rendered in the clear is a decision nobody made.
const UNREGISTERED: Axes = Axes {
    sensitivity: Sensitivity::High,
    release: ReleaseRequirement::Consent,
    mask: MaskStyle::Full,
};

/// The open extension namespace. An `x:` token is unregistered **by
/// construction**: it borrows neither an entry nor a family, however much of a
/// registered token it happens to spell.
const EXTENSION_PREFIX: &str = "x:";

/// The core table, transcribed from `claim-types.json` `registryVersion` 0.1.
///
/// `payment` and `gov` are **family** rows: they exist so that
/// `payment.somethingNew` cannot resolve to the unregistered default, whose
/// `release` is `consent` — weaker than every registered member of the family
/// it plainly belongs to. A gated family must not be leavable by inventing a
/// token.
///
/// `name` is both: an exact token — a pool that keeps one undifferentiated name
/// is using it — and a family prefix, where it can only ever tighten.
const REGISTRY: &[Entry] = &[
    Entry {
        token: "payment",
        axes: Axes {
            sensitivity: Sensitivity::High,
            release: ReleaseRequirement::StepUp,
            mask: MaskStyle::Full,
        },
    },
    Entry {
        token: "gov",
        axes: Axes {
            sensitivity: Sensitivity::High,
            release: ReleaseRequirement::StepUp,
            mask: MaskStyle::Full,
        },
    },
    Entry {
        token: "name",
        axes: Axes {
            sensitivity: Sensitivity::Normal,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::None,
        },
    },
    Entry {
        token: "name.legal",
        axes: Axes {
            sensitivity: Sensitivity::Normal,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::None,
        },
    },
    Entry {
        token: "name.given",
        axes: Axes {
            sensitivity: Sensitivity::Normal,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::None,
        },
    },
    Entry {
        token: "name.family",
        axes: Axes {
            sensitivity: Sensitivity::Normal,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::None,
        },
    },
    Entry {
        token: "name.display",
        axes: Axes {
            sensitivity: Sensitivity::Normal,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::None,
        },
    },
    // A former name is not a lesser name. It is the one a holder most often
    // keeps in order to answer a question once and never show again.
    Entry {
        token: "name.previous",
        axes: Axes {
            sensitivity: Sensitivity::High,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::Full,
        },
    },
    Entry {
        token: "person.birthDate",
        axes: Axes {
            sensitivity: Sensitivity::High,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::Full,
        },
    },
    Entry {
        token: "person.pronouns",
        axes: Axes {
            sensitivity: Sensitivity::Normal,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::None,
        },
    },
    Entry {
        token: "person.locale",
        axes: Axes {
            sensitivity: Sensitivity::Normal,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::None,
        },
    },
    Entry {
        token: "email.personal",
        axes: Axes {
            sensitivity: Sensitivity::Normal,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::EmailLocal,
        },
    },
    Entry {
        token: "email.work",
        axes: Axes {
            sensitivity: Sensitivity::Normal,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::EmailLocal,
        },
    },
    // High because a mobile number is both a strong join key and an
    // authentication factor at a great many services. Its harm is not
    // embarrassment; it is account takeover.
    Entry {
        token: "phone.mobile",
        axes: Axes {
            sensitivity: Sensitivity::High,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::Last2,
        },
    },
    Entry {
        token: "phone.landline",
        axes: Axes {
            sensitivity: Sensitivity::High,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::Last2,
        },
    },
    Entry {
        token: "address.postal",
        axes: Axes {
            sensitivity: Sensitivity::High,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::Full,
        },
    },
    // Separate from the full address on purpose: country alone answers most
    // jurisdiction questions and identifies almost nobody.
    Entry {
        token: "address.country",
        axes: Axes {
            sensitivity: Sensitivity::Normal,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::None,
        },
    },
    Entry {
        token: "gov.id.passport",
        axes: Axes {
            sensitivity: Sensitivity::High,
            release: ReleaseRequirement::StepUp,
            mask: MaskStyle::Last4,
        },
    },
    Entry {
        token: "gov.id.driverLicence",
        axes: Axes {
            sensitivity: Sensitivity::High,
            release: ReleaseRequirement::StepUp,
            mask: MaskStyle::Last4,
        },
    },
    Entry {
        token: "gov.id.national",
        axes: Axes {
            sensitivity: Sensitivity::High,
            release: ReleaseRequirement::StepUp,
            mask: MaskStyle::Last4,
        },
    },
    Entry {
        token: "gov.taxId",
        axes: Axes {
            sensitivity: Sensitivity::High,
            release: ReleaseRequirement::StepUp,
            mask: MaskStyle::Last4,
        },
    },
    Entry {
        token: "payment.card",
        axes: Axes {
            sensitivity: Sensitivity::High,
            release: ReleaseRequirement::StepUp,
            mask: MaskStyle::Last4,
        },
    },
    Entry {
        token: "payment.cardExpiry",
        axes: Axes {
            sensitivity: Sensitivity::High,
            release: ReleaseRequirement::StepUp,
            mask: MaskStyle::Full,
        },
    },
    Entry {
        token: "payment.iban",
        axes: Axes {
            sensitivity: Sensitivity::High,
            release: ReleaseRequirement::StepUp,
            mask: MaskStyle::Last4,
        },
    },
    Entry {
        token: "payment.accountNumber",
        axes: Axes {
            sensitivity: Sensitivity::High,
            release: ReleaseRequirement::StepUp,
            mask: MaskStyle::Last4,
        },
    },
    Entry {
        token: "account.handle",
        axes: Axes {
            sensitivity: Sensitivity::Normal,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::None,
        },
    },
    Entry {
        token: "url.homepage",
        axes: Axes {
            sensitivity: Sensitivity::Normal,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::None,
        },
    },
    Entry {
        token: "org.name",
        axes: Axes {
            sensitivity: Sensitivity::Normal,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::None,
        },
    },
    Entry {
        token: "org.role",
        axes: Axes {
            sensitivity: Sensitivity::Normal,
            release: ReleaseRequirement::Consent,
            mask: MaskStyle::None,
        },
    },
];

/// The registry's defaults for one claim type — §4 rules 2, 3 and 4, applied
/// per axis.
///
/// Rule 1 — the holder's own decision — is not applied here, because this
/// function is about the *type* and an override belongs to an attribute. See
/// [`sensitivity_of`].
///
/// The rules, in the order they are tried:
///
/// 2. An **exact** entry supplies every axis **as written**, and is never
///    compared against the floor. This is what lets `name` resolve to `normal`
///    and `none` even though the unregistered default is stricter on both — a
///    registry that could not say "this one is ordinary" would mask every legal
///    name in every pool, which teaches holders to reveal reflexively.
/// 3. Otherwise the **longest registered family** and the unregistered floor
///    are compared *per axis*, and the **more protective** of the two wins. Not
///    "the family wins": a family entry can only ever tighten, so `payment`
///    lends its `stepUp` to `payment.giftCard`, while `name` lends nothing at
///    all to `name.somethingNew` — which stays `high`, `full`, invisible until
///    asked for by name.
/// 4. Otherwise the floor.
///
/// Rule 3 is what makes the hierarchy load-bearing rather than merely
/// appealing, and it was missing from the first draft of the specification.
/// Without it `payment.somethingNew` resolved to a `release` of `consent`,
/// weaker than every registered member of the family it plainly belongs to.
#[must_use]
pub fn defaults_for(claim_type: &str) -> Axes {
    // Rule 4, taken first rather than last: `x:` is unregistered by
    // construction, so it must borrow neither an entry nor a family. Nothing in
    // the table starts with `x:` today, so the exact lookup below would miss
    // anyway — but the *family* lookup would not, and `x:payment.card` reading
    // as a payment instrument is the specific mistake this closes.
    if claim_type.starts_with(EXTENSION_PREFIX) {
        return UNREGISTERED;
    }

    if let Some(entry) = REGISTRY.iter().find(|e| e.token == claim_type) {
        return entry.axes;
    }

    match longest_registered_family(claim_type) {
        Some(family) => Axes {
            sensitivity: family.axes.sensitivity.min(UNREGISTERED.sensitivity),
            release: family.axes.release.min(UNREGISTERED.release),
            mask: family.axes.mask.min(UNREGISTERED.mask),
        },
        None => UNREGISTERED,
    }
}

/// The longest registered **proper** prefix of `claim_type`, on segment
/// boundaries.
///
/// Segment boundaries, not bytes. `typePrefix` on `persona/attribute/list` is
/// explicitly a byte comparison and invites the same reading here, where it
/// would be wrong in a way that matters: a byte prefix makes `paymentology` a
/// member of the `payment` family and lends it a gate it never asked for — or,
/// with the axes the other way round, a permission.
///
/// Returns the whole [`Entry`] rather than its [`Axes`] so a test can pin
/// *which* family was chosen. The shipped table has no two nested families that
/// disagree on any axis, so "longest" is currently unobservable in the result;
/// pinning the mechanism is what keeps the rule right for the first table that
/// can tell them apart.
fn longest_registered_family(claim_type: &str) -> Option<&'static Entry> {
    claim_type
        .match_indices('.')
        .map(|(i, _)| &claim_type[..i])
        .filter_map(|prefix| REGISTRY.iter().find(|e| e.token == prefix))
        // `match_indices` walks left to right, so the last match is the
        // longest — and taken from the back, the first one found is that match.
        .next_back()
}

/// The sensitivity of one attribute — §4 in full, rule 1 included.
///
/// **Store the override; derive the default.** Only a holder's deliberate
/// choice is persisted, and a resolved default is computed at read, so
/// tightening the registry protects the attributes already in the pool rather
/// than only future ones — while a holder's own decision never changes under
/// them.
///
/// An override wins in **both** directions. A holder who marks their card
/// `normal` has decided something about their own pool, and a maintainer that
/// quietly kept withholding it would be overruling the person the control
/// exists to serve.
#[must_use]
pub fn sensitivity_of(attribute: &Attribute) -> Sensitivity {
    attribute
        .sensitivity
        .unwrap_or_else(|| defaults_for(&attribute.r#type).sensitivity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Provenance, ValueType};
    use crate::store::new_attribute;

    fn attribute_of(claim_type: &str) -> Attribute {
        new_attribute(
            claim_type,
            ValueType::String,
            serde_json::json!("v"),
            Provenance::SelfAsserted,
        )
    }

    /// Rule 2. An exact entry is used as written and is never compared against
    /// the floor — which is the only way the registry can say "this one is
    /// ordinary" about a type the floor would otherwise hide.
    #[test]
    fn an_exact_entry_beats_the_family_and_the_floor() {
        // `name` is an exact entry AND a family prefix. As an entry it is
        // permissive on every axis, and rule 2 keeps it that way.
        assert_eq!(
            defaults_for("name"),
            Axes {
                sensitivity: Sensitivity::Normal,
                release: ReleaseRequirement::Consent,
                mask: MaskStyle::None,
            }
        );

        // `name.previous` sits under a permissive family and is stricter than
        // it on two axes. Rule 2 keeps that too: an exact entry tightens as
        // freely as it loosens.
        assert_eq!(
            defaults_for("name.previous"),
            Axes {
                sensitivity: Sensitivity::High,
                release: ReleaseRequirement::Consent,
                mask: MaskStyle::Full,
            }
        );

        // And an exact entry more permissive than its family on one axis:
        // `payment.card` shows its last four where the `payment` family says
        // `full`.
        assert_eq!(defaults_for("payment.card").mask, MaskStyle::Last4);
    }

    /// Rule 3, the direction it was written for. `payment` lends its `stepUp`
    /// to a token nobody has registered, so a gated family cannot be made
    /// leavable by inventing a member.
    #[test]
    fn a_family_tightens_an_unregistered_member() {
        let invented = defaults_for("payment.giftCard");
        assert_eq!(
            invented.release,
            ReleaseRequirement::StepUp,
            "an unregistered member of a gated family escaped the gate"
        );
        assert_eq!(invented.sensitivity, Sensitivity::High);
        assert_eq!(invented.mask, MaskStyle::Full);

        // The same, one level deeper, where the family is two segments above
        // the token rather than one.
        assert_eq!(
            defaults_for("gov.id.somethingNew").release,
            ReleaseRequirement::StepUp
        );
    }

    /// Rule 3, the direction that is easy to get backwards. A family entry can
    /// only ever TIGHTEN: `name` does not make an unregistered `name.*`
    /// visible.
    #[test]
    fn a_family_cannot_loosen_an_unregistered_member() {
        let invented = defaults_for("name.somethingNew");
        assert_eq!(
            invented.sensitivity,
            Sensitivity::High,
            "an invented token inherited the family's permissiveness — a name \
             nobody has reasoned about is not thereby ordinary"
        );
        assert_eq!(invented.mask, MaskStyle::Full);
        // The axis both agree on stays where both put it.
        assert_eq!(invented.release, ReleaseRequirement::Consent);
    }

    /// Rule 3's tie-break, pinned against the mechanism rather than the result.
    ///
    /// The shipped table has no two nested families that disagree on an axis,
    /// so a shortest-prefix implementation would pass every assertion above.
    #[test]
    fn the_longest_registered_family_is_the_one_that_applies() {
        let chosen = longest_registered_family("name.legal.somethingNew")
            .expect("`name.legal` is registered and is a proper prefix");
        assert_eq!(
            chosen.token, "name.legal",
            "a shorter registered prefix won over a longer one"
        );

        // Proper prefixes only. A registered token is never its own family: it
        // is rule 2's business, and a token that matched itself here would let
        // rule 3 compare an exact entry against the floor — which is precisely
        // what rule 2 says must not happen.
        assert_eq!(
            longest_registered_family("name.legal").map(|e| e.token),
            Some("name")
        );
        assert!(
            longest_registered_family("name").is_none(),
            "a single-segment token has no proper prefix to inherit from"
        );

        // Segment boundaries, not bytes.
        assert!(
            longest_registered_family("paymentology.card").is_none(),
            "a byte prefix admitted a token that is not in the family"
        );
    }

    /// Rule 4. An `x:` token borrows nothing — not an entry, not a family.
    #[test]
    fn an_extension_token_borrows_nothing() {
        for token in ["x:payment", "x:payment.card", "x:name.given", "x:anything"] {
            assert_eq!(
                defaults_for(token),
                UNREGISTERED,
                "{token} borrowed from the registry; `x:` is unregistered by construction"
            );
        }

        // The contrast is the point: strip the `x:` and two of those resolve
        // somewhere else entirely.
        assert_eq!(defaults_for("payment.card").mask, MaskStyle::Last4);
        assert_eq!(defaults_for("name.given").sensitivity, Sensitivity::Normal);
    }

    /// Rule 4 for an ordinary unknown, which is the common case for an
    /// extension vocabulary that did not use the `x:` namespace.
    #[test]
    fn an_unknown_root_gets_the_floor() {
        assert_eq!(defaults_for("wibble"), UNREGISTERED);
        assert_eq!(defaults_for("wibble.wobble"), UNREGISTERED);
    }

    /// Rule 1, in both directions. The holder's decision is the first thing
    /// consulted and the last word.
    #[test]
    fn a_holder_override_wins_over_the_registry() {
        // Tightening a type the registry calls ordinary.
        let mut ordinary = attribute_of("name.given");
        assert_eq!(sensitivity_of(&ordinary), Sensitivity::Normal);
        ordinary.sensitivity = Some(Sensitivity::High);
        assert_eq!(sensitivity_of(&ordinary), Sensitivity::High);

        // And loosening one it calls sensitive. This direction is the one an
        // implementation is tempted to refuse; refusing it would overrule the
        // person the control exists to serve.
        let mut sensitive = attribute_of("payment.card");
        assert_eq!(sensitivity_of(&sensitive), Sensitivity::High);
        sensitive.sensitivity = Some(Sensitivity::Normal);
        assert_eq!(
            sensitivity_of(&sensitive),
            Sensitivity::Normal,
            "the holder's own decision was overruled by the registry"
        );

        // An unset override is not `normal`: it records that the holder decided
        // nothing, and an unregistered token then resolves conservatively.
        assert_eq!(
            sensitivity_of(&attribute_of("x:whatever")),
            Sensitivity::High
        );
    }

    /// The transcription, checked against the source it names.
    ///
    /// Two ways for an embedded copy to be wrong that a reader will not notice:
    /// a variant spelled differently from the JSON, and a variant declared in
    /// the wrong place in the strictness order. The second is the dangerous
    /// one — `min()` is the whole of rule 3, so a misplaced variant silently
    /// resolves the wrong way round on every unregistered token.
    #[test]
    fn each_axis_matches_the_strictness_order_in_claim_types_json() {
        // Verbatim from the `strictness` block, most protective first.
        let sensitivity: Vec<String> = [Sensitivity::High, Sensitivity::Normal]
            .iter()
            .map(|v| serde_json::to_value(v).unwrap().as_str().unwrap().into())
            .collect();
        assert_eq!(sensitivity, ["high", "normal"]);

        let release: Vec<String> = [ReleaseRequirement::StepUp, ReleaseRequirement::Consent]
            .iter()
            .map(|v| serde_json::to_value(v).unwrap().as_str().unwrap().into())
            .collect();
        assert_eq!(release, ["stepUp", "consent"]);

        let mask: Vec<String> = [
            MaskStyle::Full,
            MaskStyle::Last2,
            MaskStyle::Last4,
            MaskStyle::EmailLocal,
            MaskStyle::None,
        ]
        .iter()
        .map(|v| serde_json::to_value(v).unwrap().as_str().unwrap().into())
        .collect();
        assert_eq!(mask, ["full", "last2", "last4", "emailLocal", "none"]);

        // The arrays above are the declaration order only if `min()` agrees
        // with them, which is the property rule 3 actually uses.
        assert_eq!(
            Sensitivity::High.min(Sensitivity::Normal),
            Sensitivity::High
        );
        assert_eq!(
            ReleaseRequirement::StepUp.min(ReleaseRequirement::Consent),
            ReleaseRequirement::StepUp
        );
        assert_eq!(MaskStyle::Full.min(MaskStyle::None), MaskStyle::Full);
    }

    /// The table's own invariants. A duplicate token makes the exact lookup
    /// depend on declaration order, and an `x:` row is unreachable by
    /// construction — both are transcription mistakes with no symptom.
    #[test]
    fn the_embedded_table_is_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for entry in REGISTRY {
            assert!(
                seen.insert(entry.token),
                "duplicate registry token {}",
                entry.token
            );
            assert!(
                !entry.token.starts_with(EXTENSION_PREFIX),
                "{} is in the `x:` namespace and can never be looked up",
                entry.token
            );
        }
        // The two rows rule 3 exists for. Losing either is how an invented
        // member of a gated family becomes leavable.
        assert!(seen.contains("payment"));
        assert!(seen.contains("gov"));
    }
}
