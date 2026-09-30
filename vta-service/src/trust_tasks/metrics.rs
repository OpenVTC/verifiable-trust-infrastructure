//! Metrics slice trust-task handler.
//!
//! `spec/vta/metrics/show/0.1` — this agent's current metrics snapshot,
//! reusing `did-management`'s shared `MetricsSnapshot` shape. Admin only:
//! operational counters are not a public read. Was `GET /metrics`, a
//! documented `REST_EXCEPTIONS` keep (a Prometheus scrape target) until this
//! spec landed; the Prometheus recorder is still the source of the numbers,
//! read via [`crate::metrics::PrometheusHandle::render`] and reshaped into
//! the spec's structured counters/gauges/histograms rather than handed back
//! as raw exposition text.

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::vta::metrics::show::v0_1 as metrics_show_spec;

use super::helpers::{TrustTaskOutcome, app_error_to_reject, parse_payload, success_response};
use crate::auth::AuthClaims;
use crate::server::AppState;
use vti_common::error::AppError;

/// Handler for `spec/vta/metrics/show/0.1`. Admin only.
pub(super) async fn handle_show(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    if let Err(resp) = parse_payload::<metrics_show_spec::Payload>(&doc) {
        return resp;
    }
    let Some(handle) = state.metrics_handle.as_ref() else {
        return app_error_to_reject(&doc, AppError::Internal("metrics not initialized".into()));
    };
    let snapshot = parse_prometheus_snapshot(&handle.render());
    match serde_json::from_value::<metrics_show_spec::Response>(
        serde_json::json!({ "snapshot": snapshot }),
    ) {
        Ok(r) => success_response(&doc, r),
        Err(e) => app_error_to_reject(
            &doc,
            AppError::Internal(format!("metrics snapshot does not match its schema: {e}")),
        ),
    }
}

/// One data line: the metric name (with any Prometheus type suffix still
/// attached), its label set and its value.
struct Sample {
    name: String,
    labels: std::collections::BTreeMap<String, String>,
    value: f64,
}

/// Parse the Prometheus text-exposition format `PrometheusHandle::render`
/// produces into the spec's `MetricsSnapshot` shape (`takenAt` plus
/// counters/gauges/histograms arrays). Best-effort: a line this parser
/// cannot make sense of is skipped rather than failing the whole snapshot —
/// a scrape target has always tolerated an unparsed line from a recorder
/// it doesn't fully understand.
fn parse_prometheus_snapshot(text: &str) -> Value {
    let mut kinds: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut samples: Vec<Sample> = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let mut parts = rest.split_whitespace();
            if let (Some(name), Some(kind)) = (parts.next(), parts.next()) {
                kinds.insert(name.to_string(), kind.to_string());
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if let Some(sample) = parse_sample_line(line) {
            samples.push(sample);
        }
    }

    let mut counters = Vec::new();
    let mut gauges = Vec::new();
    // Keyed by (base name, non-`le` labels) so bucket/sum/count lines for the
    // same histogram series recombine into one entry.
    let mut histograms: std::collections::BTreeMap<HistogramKey, HistogramAcc> =
        std::collections::BTreeMap::new();

    for sample in samples {
        if let Some(base) = sample.name.strip_suffix("_bucket")
            && kinds.get(base).map(String::as_str) == Some("histogram")
        {
            let mut labels = sample.labels.clone();
            let Some(le) = labels.remove("le") else {
                continue;
            };
            let le = parse_le(&le);
            let key = (base.to_string(), labels.into_iter().collect());
            let acc = histograms.entry(key).or_default();
            acc.buckets.push((le, sample.value as u64));
            continue;
        }
        if let Some(base) = sample.name.strip_suffix("_sum")
            && kinds.get(base).map(String::as_str) == Some("histogram")
        {
            let key = (base.to_string(), sample.labels.into_iter().collect());
            histograms.entry(key).or_default().sum = sample.value;
            continue;
        }
        if let Some(base) = sample.name.strip_suffix("_count")
            && kinds.get(base).map(String::as_str) == Some("histogram")
        {
            let key = (base.to_string(), sample.labels.into_iter().collect());
            histograms.entry(key).or_default().count = sample.value as u64;
            continue;
        }
        let labels: serde_json::Map<String, Value> = sample
            .labels
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        let metric = serde_json::json!({
            "name": sample.name,
            "value": sample.value,
            "labels": labels,
        });
        match kinds.get(&sample.name).map(|k| k.as_str()) {
            Some("counter") => counters.push(metric),
            _ => gauges.push(metric),
        }
    }

    let histograms: Vec<Value> = histograms
        .into_iter()
        .map(|((name, labels), acc)| {
            let mut buckets = acc.buckets;
            buckets.sort_by(|a, b| a.0.total_cmp(&b.0));
            let buckets: Vec<Value> = buckets
                .into_iter()
                .map(|(le, count)| serde_json::json!({ "le": le, "count": count }))
                .collect();
            let labels: serde_json::Map<String, Value> = labels
                .into_iter()
                .map(|(k, v)| (k, Value::String(v)))
                .collect();
            serde_json::json!({
                "name": name,
                "count": acc.count,
                "sum": acc.sum,
                "buckets": buckets,
                "labels": labels,
            })
        })
        .collect();

    serde_json::json!({
        "takenAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "counters": counters,
        "gauges": gauges,
        "histograms": histograms,
    })
}

/// A histogram series's identity: its base metric name plus its non-`le`
/// labels.
type HistogramKey = (String, Vec<(String, String)>);

#[derive(Default)]
struct HistogramAcc {
    buckets: Vec<(f64, u64)>,
    sum: f64,
    count: u64,
}

/// Parse one non-comment exposition line: `name{labels} value [timestamp]`
/// or `name value [timestamp]`.
fn parse_sample_line(line: &str) -> Option<Sample> {
    let (head, rest) = if let Some(brace) = line.find('{') {
        let close = line[brace..].find('}')? + brace;
        (&line[..brace], &line[brace + 1..close])
    } else {
        let sp = line.find(char::is_whitespace)?;
        (&line[..sp], "")
    };
    let name = head.trim().to_string();
    if name.is_empty() {
        return None;
    }
    let mut labels = std::collections::BTreeMap::new();
    if !rest.is_empty() {
        for pair in split_labels(rest) {
            if let Some((k, v)) = pair.split_once('=') {
                let v = v.trim().trim_matches('"');
                labels.insert(k.trim().to_string(), v.to_string());
            }
        }
    }
    // Whatever follows the name (or the closing brace) up to the next
    // whitespace run is the value; an optional timestamp after it is ignored.
    let after = if let Some(brace) = line.find('}') {
        &line[brace + 1..]
    } else {
        &line[head.len()..]
    };
    let value_token = after.split_whitespace().next()?;
    let value = parse_le(value_token);
    Some(Sample {
        name,
        labels,
        value,
    })
}

/// Split a Prometheus label list on top-level commas (commas inside a
/// quoted value do not split).
fn split_labels(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail = s[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

/// Prometheus spells the histogram ceiling `+Inf`; Rust's `f64::from_str`
/// wants `inf`.
fn parse_le(s: &str) -> f64 {
    match s {
        "+Inf" => f64::INFINITY,
        "-Inf" => f64::NEG_INFINITY,
        other => other.parse().unwrap_or(0.0),
    }
}
