//! Counting: an election's totals from the ballots its board counts (VTI-VOT-070).
//!
//! The caller decides which ballots count — the latest admitted under each tag, or the first,
//! by the manifest's revote rule, with replaced casts left out (VTI-VOT-041) — and passes those.
//! Every ballot passed has already passed [`crate::rules::check_ballot`]. Anyone who can read the
//! board makes the same call and gets the same totals; nothing here holds state.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use trust_tasks_rs::specs::voting::{
    ballot::cast::v0_1::Ballot,
    election::register::v0_1::{Manifest, Question},
    result::show::v0_1::QuestionResult,
};

use crate::rules::{RuleError, key, option_keys};

/// A tallied-encrypted election's rows (CONVENTIONS §9.7), from each option's decrypted total
/// (`total(question, option)`) over `n` counted casts. `abstained` is derivable only where a
/// cast selects at most one option; elsewhere it is 0.
///
/// # Errors
/// [`RuleError::InvalidManifest`] for a question other than a choice, or a total missing.
pub fn tallied_rows(
    m: &Manifest,
    total: impl Fn(&str, &str) -> Option<u64>,
    n: u64,
) -> Result<Vec<Value>, RuleError> {
    let mut rows = Vec::with_capacity(m.questions.len());
    for q in &m.questions {
        let Question::Choice { max_selections, .. } = q else {
            return Err(RuleError::InvalidManifest(
                "a tallied-encrypted election asks choices only".into(),
            ));
        };
        let qkey = key(q).unwrap_or_default();
        let mut counts = BTreeMap::new();
        let mut sum = 0u64;
        for o in option_keys(q) {
            let c = total(qkey, o)
                .ok_or_else(|| RuleError::InvalidManifest(format!("no total for {qkey}/{o}")))?;
            sum += c;
            counts.insert(o.to_string(), c);
        }
        let abstained = if max_selections.get() == 1 {
            n.saturating_sub(sum)
        } else {
            0
        };
        rows.push(json!({ "question": qkey, "choice": counts, "abstained": abstained }));
    }
    Ok(rows)
}

/// Totals per question, in the manifest's order.
///
/// Text answers are disclosed only once `ballots_counted` reaches the manifest's
/// `textReleaseThreshold` (VTI-VOT-065), and never in a `provisional` count taken while voting
/// is open: text released early could point back to the cast that produced it.
///
/// # Errors
/// [`RuleError::Serialization`] if a total cannot be expressed in the wire type.
pub fn tally<'a>(
    m: &Manifest,
    counted: impl IntoIterator<Item = &'a Ballot>,
    provisional: bool,
) -> Result<(u64, Vec<QuestionResult>), RuleError> {
    let counted: Vec<&Ballot> = counted.into_iter().collect();
    let n = counted.len() as u64;
    let release_text =
        !provisional && n >= u64::try_from(m.text_release_threshold).unwrap_or(u64::MAX);
    let mut out = Vec::with_capacity(m.questions.len());
    for q in &m.questions {
        let Some(qkey) = key(q) else {
            return Err(RuleError::InvalidManifest(
                "a question of a type this version does not serve".into(),
            ));
        };
        let opts = option_keys(q);
        let answers = counted
            .iter()
            .filter_map(|b| b.answers.iter().find(|a| a.question.as_str() == qkey));
        let mut abstained = 0u64;
        let mut row = serde_json::Map::new();
        row.insert("question".into(), json!(qkey));
        match q {
            Question::Choice { .. } => {
                let mut counts: BTreeMap<&str, u64> = opts.iter().map(|o| (*o, 0)).collect();
                for a in answers {
                    match &a.choice {
                        Some(choice) => {
                            for k in choice {
                                *counts.entry(k.as_str()).or_default() += 1;
                            }
                        }
                        None => abstained += 1,
                    }
                }
                row.insert("choice".into(), json!(counts));
            }
            Question::Ranking { .. } => {
                let mut positions: BTreeMap<&str, Vec<u64>> =
                    opts.iter().map(|o| (*o, vec![0; opts.len()])).collect();
                for a in answers {
                    match &a.ranking {
                        Some(ranking) => {
                            for (pos, k) in ranking.iter().enumerate() {
                                if let Some(p) = positions.get_mut(k.as_str()) {
                                    p[pos] += 1;
                                }
                            }
                        }
                        None => abstained += 1,
                    }
                }
                row.insert("ranking".into(), json!(positions));
            }
            Question::Score { .. } => {
                let mut sums: BTreeMap<&str, (i64, u64)> =
                    opts.iter().map(|o| (*o, (0, 0))).collect();
                for a in answers {
                    if a.scores.is_empty() {
                        abstained += 1;
                        continue;
                    }
                    for (k, v) in &a.scores {
                        let e = sums.entry(k.as_str()).or_default();
                        e.0 = e.0.saturating_add(*v);
                        e.1 += 1;
                    }
                }
                let sums: BTreeMap<&str, Value> = sums
                    .into_iter()
                    .map(|(k, (sum, count))| (k, json!({ "sum": sum, "count": count })))
                    .collect();
                row.insert("score".into(), json!(sums));
            }
            Question::Text { .. } => {
                let mut texts = Vec::new();
                for a in answers {
                    match &a.text {
                        Some(t) => texts.push(t.as_str().to_string()),
                        None => abstained += 1,
                    }
                }
                if release_text {
                    row.insert("text".into(), json!(texts));
                } else {
                    row.insert("withheld".into(), json!(true));
                }
            }
            _ => {
                return Err(RuleError::InvalidManifest(
                    "a question of a type this version does not serve".into(),
                ));
            }
        }
        row.insert("abstained".into(), json!(abstained));
        out.push(
            serde_json::from_value(Value::Object(row))
                .map_err(|e| RuleError::Serialization(e.to_string()))?,
        );
    }
    Ok((n, out))
}
