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

impl Sensitivity {
    /// Every variant, most protective first — the declaration order, which is
    /// what makes `Ord` mean "more protective" on this axis.
    ///
    /// Written out rather than derived because Rust has no reflection over
    /// variants; the test below walks it against `Ord` so a variant added
    /// without being listed, or listed out of order, fails rather than being
    /// served as a quietly wrong ordering to every client.
    pub const MOST_PROTECTIVE_FIRST: &'static [Self] = &[Self::High, Self::Normal];
}

impl ReleaseRequirement {
    /// Every variant, most protective first. See [`Sensitivity::MOST_PROTECTIVE_FIRST`].
    pub const MOST_PROTECTIVE_FIRST: &'static [Self] = &[Self::StepUp, Self::Consent];
}

impl MaskStyle {
    /// Every variant, most protective first. See [`Sensitivity::MOST_PROTECTIVE_FIRST`].
    pub const MOST_PROTECTIVE_FIRST: &'static [Self] = &[
        Self::Full,
        Self::Last2,
        Self::Last4,
        Self::EmailLocal,
        Self::None,
    ];
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

    if let Some((_, axes)) = declared().find(|(token, _)| *token == claim_type) {
        return axes;
    }

    match longest_registered_family(claim_type) {
        Some((_, axes)) => Axes {
            sensitivity: axes.sensitivity.min(UNREGISTERED.sensitivity),
            release: axes.release.min(UNREGISTERED.release),
            mask: axes.mask.min(UNREGISTERED.mask),
        },
        None => UNREGISTERED,
    }
}

/// Every declared row: the core table, and this deployment's extensions.
///
/// **Extensions come first, and the order is the rule.** An extension may only
/// ever be *more* protective than what core resolves for the same token
/// ([`install_extensions`] refuses anything else), so taking the first match
/// gives the tighter answer where both declare a token, and the core answer
/// everywhere else.
///
/// One iterator rather than two lookups because §4's rules — exact, then
/// longest family, then floor — are one walk over one table. A second table
/// walked separately is two tables that resolve differently, and the family
/// step is where that would show: an extension family that the exact step knew
/// about and the walk did not.
fn declared() -> impl Iterator<Item = (&'static str, Axes)> {
    extensions()
        .iter()
        .map(|e| (e.token.as_str(), e.axes))
        .chain(REGISTRY.iter().map(|e| (e.token, e.axes)))
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
fn longest_registered_family(claim_type: &str) -> Option<(&'static str, Axes)> {
    claim_type
        .match_indices('.')
        .map(|(i, _)| &claim_type[..i])
        .filter_map(|prefix| declared().find(|(token, _)| *token == prefix))
        // `match_indices` walks left to right, so the last match is the
        // longest — and taken from the back, the first one found is that match.
        .next_back()
}

/// The registry as a client needs to receive it: every row, the floor, and the
/// per-axis strictness ordering.
///
/// Served by `persona/claim-types/list` so a client resolves against **this**
/// agent's table rather than a copy compiled into its own build. The three
/// parts are inseparable: §4 rule 3 takes the longest registered prefix and the
/// unregistered floor and keeps whichever is *more protective*, which a client
/// cannot compute from the rows alone.
///
/// Rows are returned exactly as this crate holds them, in table order. Family
/// prefixes (`payment`, `gov`) and exact tokens (`name.legal`) are
/// undistinguished, because which one a row is depends on the token being
/// resolved — and marking them would invite a client to walk only one kind,
/// which is the hole that let a gated family be escaped by inventing a member.
///
/// **`minimumSet` and `oidc` are deliberately absent.** The spec makes both
/// optional, and this agent's table does not carry them: nothing here resolves
/// against either. Transcribing them in at the serving layer would be a second
/// copy of data this crate does not use — which is the thing this task exists
/// to end, one layer down.
#[must_use]
pub fn registry_listing() -> RegistryListing {
    RegistryListing {
        registry_version: REGISTRY_VERSION,
        // Core first, then this deployment's extensions — the whole table a
        // client must resolve against, because the client runs §4 over what it
        // is served and the agent runs it over what it holds. Serving core only
        // while resolving over both is the disagreement this task exists to
        // prevent, with the client's answer the looser of the two.
        entries: REGISTRY
            .iter()
            .map(|e| RegistryRow {
                claim_type: e.token,
                axes: e.axes,
            })
            .chain(extensions().iter().map(|e| RegistryRow {
                claim_type: e.token.as_str(),
                axes: e.axes,
            }))
            .collect(),
        unregistered: UNREGISTERED,
        strictness: Strictness {
            // Each axis most protective first — the same order the enums are
            // declared in, which is what makes `min()` mean "more protective"
            // throughout this module. Derived from the enums rather than
            // written out again, so the served ordering cannot disagree with
            // the one the resolution actually uses.
            sensitivity: Sensitivity::MOST_PROTECTIVE_FIRST,
            release: ReleaseRequirement::MOST_PROTECTIVE_FIRST,
            mask: MaskStyle::MOST_PROTECTIVE_FIRST,
        },
    }
}

// ── Deployment extension types ─────────────────────────────────────────────
//
// ## Why this exists
//
// The core table is transcribed from the published registry and is the same
// everywhere. A deployment's own vocabulary is not: `profile.github`,
// `employer`, whatever a particular ecosystem keeps about its people. Until
// now the only way to teach an agent one of those words was a pull request
// against the specification repository, a publish, a hand-transcription into
// the table above, a release and a deploy — five steps across two repositories
// to add a word, two of them manual copying. So nobody did, every local token
// resolved to the floor, and holders saw every value they had invented a name
// for masked as though it were a passport number.
//
// `CLAIM-TYPES.md` §6 anticipated this: the served-table task was "worth doing
// when the first extension type ships, not before". It ships now.
//
// ## What an operator may declare, and what they may not
//
// **Anything the core table does not cover.** A token core has never heard of
// resolves to the floor *because nobody has reasoned about it* — §4 rule 3
// says so in as many words — and an operator declaring it is that reasoning
// arriving. This is the case the feature exists for.
//
// **Only tightenings of anything core does cover.** An entry may not resolve
// looser on any axis than core already resolves for that same token, whether
// core covers it exactly (`email.work`) or through a family (`payment.giftCard`
// under `payment`). Otherwise a deployment could declare `gov.id.passport`
// unremarkable, or invent a `payment.*` member outside its family's gate — and
// the family walk exists precisely to stop the second one.
//
// **Never an `x:` token.** §4's last rule makes the extension namespace
// unregistered by construction, and every client implements it that way. An
// agent that declared one would serve a row no client would honour.
//
// ## Configured, not administered
//
// Installed once at startup from a file the deployment supplies. Not an admin
// Trust Task: serving a new task URI requires a published spec (the dispatcher
// harness refuses an unspecced one), so a runtime-managed registry is a
// larger, upstream-first change. A file is diffable, reviewable, and belongs to
// whoever owns the deployment — which is who this is for.

/// One claim type a deployment declares for itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionEntry {
    /// The vocabulary token, dotted most-general-segment-first.
    pub token: String,
    /// Its three axes, exactly as a core row carries them.
    pub axes: Axes,
}

/// Why a deployment's extension table was refused.
///
/// Every one of these fails startup rather than dropping the offending row.
/// A registry that silently served fewer types than its operator wrote is one
/// where a tightening they believed was in force is not, and the values it was
/// meant to protect are the ones they would find out about last.
#[derive(Debug, PartialEq, Eq)]
pub enum ExtensionError {
    /// The file was not the shape a table has.
    Malformed(String),
    /// `x:` is unregistered by construction — see §4's last rule.
    ExtensionNamespace(String),
    /// Not a vocabulary token: empty, or with an empty or non-alphanumeric
    /// segment. The core table's own tokens are the model.
    NotAToken(String),
    /// The same token declared twice, which leaves what it resolves to
    /// dependent on the order rows happen to sit in.
    Duplicate(String),
    /// The token is one the core table already covers, and this row is looser
    /// on `axis` than core resolves it. Carries both so the message can say
    /// what it would have weakened.
    Loosens {
        token: String,
        axis: &'static str,
        core: String,
        declared: String,
    },
    /// [`install_extensions`] was called twice. The table is read by the
    /// disclosure gate and by the read-path withholding, and swapping it under
    /// a running agent would mean two requests in the same second resolving
    /// differently.
    AlreadyInstalled,
}

impl std::fmt::Display for ExtensionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "claim-type extensions are malformed: {why}"),
            Self::ExtensionNamespace(t) => write!(
                f,
                "`{t}` is in the `x:` namespace, which is unregistered by construction — \
                 no client would honour a row declaring one"
            ),
            Self::NotAToken(t) => write!(f, "`{t}` is not a vocabulary token"),
            Self::Duplicate(t) => write!(f, "`{t}` is declared twice"),
            Self::Loosens {
                token,
                axis,
                core,
                declared,
            } => write!(
                f,
                "`{token}` would weaken {axis} from `{core}` to `{declared}`; the core table \
                 already covers this token, and an extension may only tighten"
            ),
            Self::AlreadyInstalled => write!(f, "claim-type extensions are already installed"),
        }
    }
}

impl std::error::Error for ExtensionError {}

static EXTENSIONS: std::sync::OnceLock<Vec<ExtensionEntry>> = std::sync::OnceLock::new();

/// This deployment's extension rows — empty until [`install_extensions`] runs,
/// which is the state every test and every default deployment is in.
fn extensions() -> &'static [ExtensionEntry] {
    EXTENSIONS.get().map(Vec::as_slice).unwrap_or(&[])
}

/// Validate a deployment's extension table and install it, once.
///
/// Called at startup, before the first request. Every rule in the module
/// comment above is enforced here rather than at the file's edge, so a caller
/// that builds rows some other way cannot skip them.
///
/// # Errors
///
/// Any row that is not a token, is in the `x:` namespace, repeats another, or
/// loosens what the core table resolves — and calling twice.
pub fn install_extensions(entries: Vec<ExtensionEntry>) -> Result<(), ExtensionError> {
    validate(&entries)?;
    EXTENSIONS
        .set(entries)
        .map_err(|_| ExtensionError::AlreadyInstalled)
}

/// Read a deployment's extension table from the JSON an operator wrote.
///
/// The rows are the same shape the agent serves — `type` plus the three axes —
/// so an operator can copy a row out of `persona/claim-types/list`, change it,
/// and put it back. Both the bare array and the `{"entries": [...]}` wrapper
/// are accepted for that reason: one is what the file looks like, the other is
/// what the served document looks like, and being strict about which would be
/// a rule with nothing behind it.
///
/// Parsing only — every rule lives in [`install_extensions`], so a caller who
/// builds rows another way gets the same checks.
///
/// # Errors
///
/// Anything that is not that shape, including an unknown axis value. An
/// unknown value is refused rather than defaulted: a typo'd `"sensitivty"`
/// silently becoming the floor would look like a working tightening, and a
/// typo'd `"hgih"` silently becoming `normal` would look like a working
/// loosening.
pub fn parse_extensions(json: &str) -> Result<Vec<ExtensionEntry>, ExtensionError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Row {
        r#type: String,
        sensitivity: Sensitivity,
        release: ReleaseRequirement,
        mask: MaskStyle,
    }
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum File {
        Wrapped { entries: Vec<Row> },
        Bare(Vec<Row>),
    }

    let parsed: File =
        serde_json::from_str(json).map_err(|e| ExtensionError::Malformed(e.to_string()))?;
    let rows = match parsed {
        File::Wrapped { entries } => entries,
        File::Bare(rows) => rows,
    };
    Ok(rows
        .into_iter()
        .map(|r| ExtensionEntry {
            token: r.r#type,
            axes: Axes {
                sensitivity: r.sensitivity,
                release: r.release,
                mask: r.mask,
            },
        })
        .collect())
}

/// The checks, separated from installation so they can be tested without
/// consuming the process-wide slot — a `OnceLock` takes one value per process,
/// and a test suite needs to try many.
fn validate(entries: &[ExtensionEntry]) -> Result<(), ExtensionError> {
    let mut seen = std::collections::BTreeSet::new();
    for e in entries {
        if e.token.starts_with(EXTENSION_PREFIX) {
            return Err(ExtensionError::ExtensionNamespace(e.token.clone()));
        }
        if !is_token(&e.token) {
            return Err(ExtensionError::NotAToken(e.token.clone()));
        }
        if !seen.insert(e.token.as_str()) {
            return Err(ExtensionError::Duplicate(e.token.clone()));
        }
        // Compared against what **core alone** resolves, which is the question
        // being asked: may this deployment say something weaker than the
        // published registry does about a token the published registry knows?
        if core_covers(&e.token) {
            let core = core_defaults_for(&e.token);
            check_tightens(&e.token, e.axes, core)?;
        }
    }
    Ok(())
}

/// A token is one or more non-empty segments of ASCII alphanumerics, separated
/// by dots. Deliberately narrow: the core table's own tokens all satisfy it,
/// and a token carrying a space or a slash is a file that has been edited into
/// something that is not a vocabulary.
fn is_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .split('.')
            .all(|seg| !seg.is_empty() && seg.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// Whether the **core** table has anything to say about this token — exactly,
/// or through a family. Distinct from "resolves to something": every token
/// resolves, most of them to the floor, and the floor is the answer that means
/// nobody has looked.
fn core_covers(token: &str) -> bool {
    REGISTRY.iter().any(|e| e.token == token)
        || token
            .match_indices('.')
            .map(|(i, _)| &token[..i])
            .any(|prefix| REGISTRY.iter().any(|e| e.token == prefix))
}

/// [`defaults_for`] over the core table only, for the comparison above.
fn core_defaults_for(token: &str) -> Axes {
    if let Some(entry) = REGISTRY.iter().find(|e| e.token == token) {
        return entry.axes;
    }
    match token
        .match_indices('.')
        .map(|(i, _)| &token[..i])
        .filter_map(|prefix| REGISTRY.iter().find(|e| e.token == prefix))
        .next_back()
    {
        Some(family) => Axes {
            sensitivity: family.axes.sensitivity.min(UNREGISTERED.sensitivity),
            release: family.axes.release.min(UNREGISTERED.release),
            mask: family.axes.mask.min(UNREGISTERED.mask),
        },
        None => UNREGISTERED,
    }
}

/// Each axis of `declared` must be at least as protective as `core`.
///
/// `min` is "more protective" throughout this module, because each enum is
/// declared most-protective-first — the same ordering served as `strictness`,
/// so an operator can check this rule themselves against what the agent
/// publishes.
fn check_tightens(token: &str, declared: Axes, core: Axes) -> Result<(), ExtensionError> {
    let loosens = |axis, core_v: String, declared_v: String| ExtensionError::Loosens {
        token: token.to_owned(),
        axis,
        core: core_v,
        declared: declared_v,
    };
    if declared.sensitivity.min(core.sensitivity) != declared.sensitivity {
        return Err(loosens(
            "sensitivity",
            wire_name(core.sensitivity),
            wire_name(declared.sensitivity),
        ));
    }
    if declared.release.min(core.release) != declared.release {
        return Err(loosens(
            "release",
            wire_name(core.release),
            wire_name(declared.release),
        ));
    }
    if declared.mask.min(core.mask) != declared.mask {
        return Err(loosens(
            "mask",
            wire_name(core.mask),
            wire_name(declared.mask),
        ));
    }
    Ok(())
}

/// An axis value as the wire spells it, for a message an operator reads
/// alongside what the agent serves. Via `Serialize` so the two cannot drift:
/// the same rename that produces the served table produces this word.
fn wire_name<T: Serialize>(v: T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// One row of [`registry_listing`].
#[derive(Clone, Copy, Debug)]
pub struct RegistryRow {
    pub claim_type: &'static str,
    pub axes: Axes,
}

/// The per-axis orderings, most protective first.
#[derive(Clone, Copy, Debug)]
pub struct Strictness {
    pub sensitivity: &'static [Sensitivity],
    pub release: &'static [ReleaseRequirement],
    pub mask: &'static [MaskStyle],
}

/// Everything `persona/claim-types/list` returns.
#[derive(Clone, Debug)]
pub struct RegistryListing {
    pub registry_version: &'static str,
    pub entries: Vec<RegistryRow>,
    pub unregistered: Axes,
    pub strictness: Strictness,
}

/// The version of `claim-types.json` this table was transcribed from.
///
/// A client caches on this, so it moves when the table moves — not when this
/// crate is released.
const REGISTRY_VERSION: &str = "0.1";

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

/// What it takes to let one attribute leave — §4 per the `release` axis.
///
/// Same shape as [`sensitivity_of`], and an override wins in **both**
/// directions for the same reason: the holder is the principal, and an agent
/// that kept gating a value its owner had decided needed no gate would be
/// overruling the person the control exists to serve.
///
/// That the loosening direction is available is not a hole, because of where
/// the write happens. `release` is set through `persona/attribute/put`, which
/// is **holder-scoped** — above the boundary, refused to every context-scoped
/// caller and to every application inside a context. A verifier cannot reach
/// it, and neither can the site asking for the disclosure. The only party who
/// can relax the gate is the one it protects.
///
/// Worth considering separately: whether *loosening* should itself require a
/// step-up, so the act of turning a gate off is gated. That is a real idea and
/// deliberately not built here — it is a new gate, not this one.
#[must_use]
pub fn release_of(attribute: &Attribute) -> ReleaseRequirement {
    attribute
        .release
        .unwrap_or_else(|| defaults_for(&attribute.r#type).release)
}

/// The `release` of a claim that has already been pushed into a context.
///
/// The pool is not readable from here — that is the boundary — so the holder's
/// override has to have travelled *down* with the value when the binding was
/// written. `None` means the projection carries no decision and the registry
/// default answers, which is also what every binding written before this field
/// existed says.
#[must_use]
pub fn release_of_claim(
    claim_type: &str,
    override_: Option<ReleaseRequirement>,
) -> ReleaseRequirement {
    override_.unwrap_or_else(|| defaults_for(claim_type).release)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The served ordering IS the resolution ordering.
    ///
    /// `MOST_PROTECTIVE_FIRST` is hand-written — Rust cannot enumerate variants
    /// — so it can disagree with `Ord`, which is what every "more protective
    /// wins" comparison in this module actually uses. A disagreement would be
    /// silent and would be *served to every client* as the rule to resolve by.
    /// So: each list must be sorted ascending under `Ord`, and must be
    /// complete.
    #[test]
    fn the_served_strictness_matches_the_ordering_resolution_uses() {
        fn ascending<T: Ord + std::fmt::Debug + Copy>(xs: &[T], axis: &str) {
            let mut sorted = xs.to_vec();
            sorted.sort();
            assert_eq!(
                xs.to_vec(),
                sorted,
                "{axis}: MOST_PROTECTIVE_FIRST disagrees with Ord, so the ordering served to \
                 clients is not the one this module resolves by"
            );
        }
        ascending(Sensitivity::MOST_PROTECTIVE_FIRST, "sensitivity");
        ascending(ReleaseRequirement::MOST_PROTECTIVE_FIRST, "release");
        ascending(MaskStyle::MOST_PROTECTIVE_FIRST, "mask");

        // Completeness: the floor is the most protective value on every axis,
        // so it must be the first element. A variant added above it and not
        // listed would fail here.
        assert_eq!(
            Sensitivity::MOST_PROTECTIVE_FIRST[0],
            UNREGISTERED.sensitivity
        );
        assert_eq!(MaskStyle::MOST_PROTECTIVE_FIRST[0], UNREGISTERED.mask);
    }

    /// The listing carries the three parts a client needs, and every row of the
    /// table it actually resolves against.
    #[test]
    fn the_listing_serves_the_table_this_agent_resolves_by() {
        let l = registry_listing();
        assert_eq!(
            l.entries.len(),
            REGISTRY.len(),
            "rows dropped on the way out"
        );
        for (row, entry) in l.entries.iter().zip(REGISTRY.iter()) {
            assert_eq!(row.claim_type, entry.token);
            assert_eq!(row.axes, entry.axes);
        }
        assert_eq!(l.unregistered, UNREGISTERED);
        assert_eq!(l.registry_version, "0.1");

        // The family rows are present and undistinguished — a client walking
        // prefixes needs them, and nothing marks them as different.
        assert!(l.entries.iter().any(|r| r.claim_type == "payment"));
        assert!(l.entries.iter().any(|r| r.claim_type == "gov"));
    }
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
            chosen.0, "name.legal",
            "a shorter registered prefix won over a longer one"
        );

        // Proper prefixes only. A registered token is never its own family: it
        // is rule 2's business, and a token that matched itself here would let
        // rule 3 compare an exact entry against the floor — which is precisely
        // what rule 2 says must not happen.
        assert_eq!(
            longest_registered_family("name.legal").map(|e| e.0),
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

    // ── Deployment extension types ─────────────────────────────────────────
    //
    // The rules are the whole feature: an operator may name what the published
    // registry has never heard of, and may tighten what it has, and may do
    // nothing else. Each test below is one of the ways the second half fails
    // if nobody checks it.

    fn ext(
        token: &str,
        sensitivity: Sensitivity,
        release: ReleaseRequirement,
        mask: MaskStyle,
    ) -> ExtensionEntry {
        ExtensionEntry {
            token: token.to_owned(),
            axes: Axes {
                sensitivity,
                release,
                mask,
            },
        }
    }

    #[test]
    fn a_token_core_never_heard_of_may_be_declared_freely() {
        // The case the feature exists for. `profile.github` resolves to the
        // floor today *because nobody has reasoned about it*, and an operator
        // declaring it is that reasoning arriving.
        let rows = vec![ext(
            "profile.github",
            Sensitivity::Normal,
            ReleaseRequirement::Consent,
            MaskStyle::None,
        )];
        assert_eq!(validate(&rows), Ok(()));
    }

    #[test]
    fn an_extension_may_tighten_a_token_core_declares() {
        // `email.work` is `normal`/`consent`/`emailLocal`. A deployment
        // deciding an address is worth withholding entirely is allowed to say
        // so — that direction takes nothing away from anyone.
        let rows = vec![ext(
            "email.work",
            Sensitivity::High,
            ReleaseRequirement::StepUp,
            MaskStyle::Full,
        )];
        assert_eq!(validate(&rows), Ok(()));
    }

    #[test]
    fn an_extension_may_not_loosen_a_token_core_declares() {
        // The one that matters. A deployment declaring a passport
        // unremarkable would be serving every client a row saying so.
        let rows = vec![ext(
            "gov.id.passport",
            Sensitivity::Normal,
            ReleaseRequirement::Consent,
            MaskStyle::None,
        )];
        match validate(&rows) {
            Err(ExtensionError::Loosens { token, axis, .. }) => {
                assert_eq!(token, "gov.id.passport");
                assert_eq!(
                    axis, "sensitivity",
                    "the first axis it weakens is the one named"
                );
            }
            other => panic!("expected a loosening refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_invented_member_cannot_escape_its_family() {
        // `payment.giftCard` is not in the table, but `payment` is, and §4
        // rule 3 resolves the member through the family. Without the family
        // being consulted here, inventing a member would be the way around
        // every gate the family carries — which is the exact hole rule 3 was
        // added to close.
        let rows = vec![ext(
            "payment.giftCard",
            Sensitivity::Normal,
            ReleaseRequirement::Consent,
            MaskStyle::None,
        )];
        assert!(matches!(
            validate(&rows),
            Err(ExtensionError::Loosens { .. })
        ));
    }

    #[test]
    fn an_extension_namespace_token_is_refused() {
        // §4's last rule makes `x:` unregistered by construction. An agent
        // declaring one would serve a row no conforming client would honour,
        // so the disagreement is refused at the source.
        let rows = vec![ext(
            "x:profile.github",
            Sensitivity::Normal,
            ReleaseRequirement::Consent,
            MaskStyle::None,
        )];
        assert!(matches!(
            validate(&rows),
            Err(ExtensionError::ExtensionNamespace(_))
        ));
    }

    #[test]
    fn a_token_that_is_not_a_token_is_refused() {
        for bad in [
            "",
            "has space",
            "trailing.",
            ".leading",
            "two..dots",
            "slash/es",
        ] {
            let rows = vec![ext(
                bad,
                Sensitivity::High,
                ReleaseRequirement::StepUp,
                MaskStyle::Full,
            )];
            assert!(
                matches!(validate(&rows), Err(ExtensionError::NotAToken(_))),
                "`{bad}` should not be a token"
            );
        }
    }

    #[test]
    fn a_repeated_token_is_refused_rather_than_last_one_wins() {
        // Two rows for one token leave what it resolves to dependent on the
        // order they happen to sit in the file.
        let rows = vec![
            ext(
                "profile.github",
                Sensitivity::Normal,
                ReleaseRequirement::Consent,
                MaskStyle::None,
            ),
            ext(
                "profile.github",
                Sensitivity::High,
                ReleaseRequirement::StepUp,
                MaskStyle::Full,
            ),
        ];
        assert!(matches!(validate(&rows), Err(ExtensionError::Duplicate(_))));
    }

    #[test]
    fn the_file_is_read_in_both_shapes_an_operator_would_write() {
        let bare = r#"[{"type":"profile.github","sensitivity":"normal","release":"consent","mask":"none"}]"#;
        let wrapped = r#"{"entries":[{"type":"profile.github","sensitivity":"normal","release":"consent","mask":"none"}]}"#;
        let expected = vec![ext(
            "profile.github",
            Sensitivity::Normal,
            ReleaseRequirement::Consent,
            MaskStyle::None,
        )];
        assert_eq!(parse_extensions(bare).unwrap(), expected);
        assert_eq!(
            parse_extensions(wrapped).unwrap(),
            expected,
            "as copied out of the served table"
        );
    }

    #[test]
    fn an_unknown_axis_value_is_refused_rather_than_defaulted() {
        // A typo that defaulted would look like a working rule: `hgih` reading
        // as `normal` is a loosening nobody wrote and nobody would see.
        let typo =
            r#"[{"type":"profile.github","sensitivity":"hgih","release":"consent","mask":"none"}]"#;
        assert!(matches!(
            parse_extensions(typo),
            Err(ExtensionError::Malformed(_))
        ));
        let misspelt_member =
            r#"[{"type":"profile.github","sensitivty":"high","release":"consent","mask":"none"}]"#;
        assert!(matches!(
            parse_extensions(misspelt_member),
            Err(ExtensionError::Malformed(_))
        ));
    }
}
