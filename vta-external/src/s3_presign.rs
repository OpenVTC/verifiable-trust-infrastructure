//! `s3-static-presign`: S3-compatible stores that cannot federate (R2, B2,
//! MinIO). The access key's secret half never leaves the custodian; a consumer
//! gets one presigned URL per issuance — one method, one object, minutes.
//!
//! Presigning is AWS Signature Version 4 in query-string form ("Authenticating
//! Requests: Using Query Parameters" in the S3 API reference), a computation
//! inside the custodian with no network. Every value that reaches the canonical
//! request was validated first (`crate::scope`), and is URI-encoded by the
//! SigV4 rules here rather than formatted into a string.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use vta_sdk::sealed_transfer::ExternalCredentialPayload;

use crate::driver::{
    BatchIssueRequest, DriverError, ExternalAuthDriver, IssueRequest, Issued, SettingsError,
};
use crate::model::{AccountRecord, rfc3339};

/// The driver.
pub struct S3StaticPresign;

/// The settings this driver reads, checked once.
struct Settings {
    endpoint: Url,
    region: String,
    bucket: String,
    path_style: bool,
    access_key_id: String,
    probe_prefix: Option<String>,
}

fn settings(v: &Value) -> Result<Settings, SettingsError> {
    let s = |k: &'static str| {
        v.get(k)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| SettingsError::new(k, format!("{k} is required")))
    };
    let bad = |member: &'static str, why: &str| SettingsError::new(member, why);
    let endpoint =
        Url::parse(&s("endpoint")?).map_err(|e| SettingsError::new("endpoint", e.to_string()))?;
    if endpoint.scheme() != "https" {
        return Err(bad("endpoint", "must be https"));
    }
    if endpoint.host_str().is_none() {
        return Err(bad("endpoint", "has no host"));
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() || endpoint.path() != "/" {
        return Err(bad(
            "endpoint",
            "must be a bare origin, with no path or query",
        ));
    }
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err(bad("endpoint", "must not carry credentials"));
    }
    let region = s("region")?;
    if region.is_empty()
        || !region
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(bad("region", "must be lowercase letters, digits and '-'"));
    }
    let bucket = s("bucket")?;
    let bucket_ok = (3..=63).contains(&bucket.len())
        && bucket
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        && !bucket.starts_with(['.', '-'])
        && !bucket.ends_with(['.', '-']);
    if !bucket_ok {
        return Err(bad("bucket", "is not a valid bucket name"));
    }
    let access_key_id = s("accessKeyId")?;
    if access_key_id.is_empty() || !access_key_id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(bad("accessKeyId", "must be letters and digits"));
    }
    let probe_prefix = v
        .get("probePrefix")
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(p) = &probe_prefix {
        crate::scope::validate_prefix(p)
            .map_err(|e| SettingsError::new("probePrefix", e.to_string()))?;
    }
    Ok(Settings {
        endpoint,
        region,
        bucket,
        path_style: v.get("pathStyle").and_then(Value::as_bool).unwrap_or(false),
        access_key_id,
        probe_prefix,
    })
}

/// The account's access key id, for checking a sealed secret's claim.
pub fn access_key_id(settings_value: &Value) -> Option<&str> {
    settings_value.get("accessKeyId").and_then(Value::as_str)
}

/// A presigned request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presigned {
    pub method: &'static str,
    pub url: String,
}

/// The HTTP method for an object action.
pub fn method_for(action: &str) -> Option<&'static str> {
    match action {
        "put" => Some("PUT"),
        "get" => Some("GET"),
        "delete" => Some("DELETE"),
        _ => None,
    }
}

/// SigV4 `UriEncode`: everything but the unreserved set is percent-encoded,
/// upper-case hex; `/` is kept only where `keep_slash` (the path).
fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Presign `method` on `key` (the object key, already validated) for
/// `expires_seconds` from `now`, signing only `host`. Pure: no clock, no network.
fn presign(
    s: &Settings,
    secret: &str,
    method: &'static str,
    key: &str,
    expires_seconds: u32,
    now: DateTime<Utc>,
) -> Presigned {
    presign_with(s, secret, method, key, &[], &[], expires_seconds, now).0
}

/// Presign `method` on `key` with `query` added to the signed query and
/// `headers` (name as returned, value) signed beside `host`. Every name and value
/// is percent-encoded by the SigV4 rules, never formatted in. Returns the request
/// and the headers it must carry, exactly as signed. Pure.
#[allow(clippy::too_many_arguments)]
fn presign_with(
    s: &Settings,
    secret: &str,
    method: &'static str,
    key: &str,
    query: &[(&str, String)],
    headers: &[(&'static str, String)],
    expires_seconds: u32,
    now: DateTime<Utc>,
) -> (Presigned, std::collections::BTreeMap<String, String>) {
    let host = match (s.path_style, s.endpoint.host_str()) {
        (_, None) => unreachable!("validated: endpoint has a host"),
        (true, Some(h)) => h.to_string(),
        (false, Some(h)) => format!("{}.{h}", s.bucket),
    };
    let host = match s.endpoint.port() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    };
    let path = if s.path_style {
        format!("/{}/{}", s.bucket, key)
    } else {
        format!("/{key}")
    };
    let canonical_uri = uri_encode(&path, true);

    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let scope = format!("{date}/{}/s3/aws4_request", s.region);
    let credential = format!("{}/{scope}", s.access_key_id);

    // The signed headers: `host` and those asked for, by lower-case name, sorted.
    let mut canon_headers: Vec<(String, String)> = vec![("host".into(), host.clone())];
    canon_headers.extend(
        headers
            .iter()
            .map(|(n, v)| (n.to_ascii_lowercase(), v.trim().to_string())),
    );
    canon_headers.sort();
    let signed_headers = canon_headers
        .iter()
        .map(|(n, _)| n.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let mut params: Vec<(String, String)> = vec![
        ("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()),
        ("X-Amz-Credential".into(), credential),
        ("X-Amz-Date".into(), amz_date.clone()),
        ("X-Amz-Expires".into(), expires_seconds.to_string()),
        ("X-Amz-SignedHeaders".into(), signed_headers.clone()),
    ];
    params.extend(query.iter().map(|(k, v)| (k.to_string(), v.clone())));
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    encoded.sort();
    let canonical_query = encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_header_block: String = canon_headers
        .iter()
        .map(|(n, v)| format!("{n}:{v}\n"))
        .collect();
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_header_block}\n{signed_headers}\nUNSIGNED-PAYLOAD"
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let k_date = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, s.region.as_bytes());
    let k_service = hmac(&k_region, b"s3");
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));

    let returned = headers
        .iter()
        .map(|(n, v)| (n.to_string(), v.clone()))
        .collect();
    (
        Presigned {
            method,
            url: format!(
                "{}://{host}{canonical_uri}?{canonical_query}&X-Amz-Signature={signature}",
                s.endpoint.scheme()
            ),
        },
        returned,
    )
}

/// One operation of a batch as SigV4 parts: method, signed query, signed
/// headers — exactly the specification's table (`issue/0.2` item 10), and
/// nothing else.
/// A signed query or header list: names fixed by the table, values validated.
type Signed = Vec<(&'static str, String)>;

fn operation_parts(
    op: &crate::batch::PresignRequest,
    upload_id: Option<&str>,
) -> (&'static str, Signed, Signed) {
    use crate::batch::PresignRequest as Op;
    let id = || upload_id.unwrap_or_default().to_string();
    match op {
        Op::Put {
            checksum_sha256,
            content_length,
        } => (
            "PUT",
            vec![],
            vec![
                ("Content-Length", content_length.to_string()),
                ("x-amz-checksum-sha256", checksum_sha256.to_string()),
            ],
        ),
        Op::Get => ("GET", vec![], vec![]),
        Op::Head => (
            "HEAD",
            vec![],
            vec![("x-amz-checksum-mode", "ENABLED".into())],
        ),
        Op::Delete => ("DELETE", vec![], vec![]),
        Op::CreateMultipart => (
            "POST",
            vec![("uploads", String::new())],
            vec![("x-amz-checksum-algorithm", "SHA256".into())],
        ),
        Op::UploadPart {
            checksum_sha256,
            content_length,
            part_number,
        } => (
            "PUT",
            vec![("partNumber", part_number.to_string()), ("uploadId", id())],
            vec![
                ("Content-Length", content_length.to_string()),
                ("x-amz-checksum-sha256", checksum_sha256.to_string()),
            ],
        ),
        Op::ListParts { part_number_marker } => {
            let mut q = vec![("uploadId", id()), ("max-parts", "1000".into())];
            if let Some(m) = part_number_marker {
                q.push(("part-number-marker", m.to_string()));
            }
            ("GET", q, vec![])
        }
        Op::CompleteMultipart { content_length } => (
            "POST",
            vec![("uploadId", id())],
            vec![("x-amz-mp-object-size", content_length.to_string())],
        ),
        Op::AbortMultipart => ("DELETE", vec![("uploadId", id())], vec![]),
        // `check_batch` refuses an operation this build does not know.
        _ => ("GET", vec![], vec![]),
    }
}

/// Presign every operation of `batch`, in order, for `ttl` seconds from `now`.
fn presign_batch(
    s: &Settings,
    secret: &str,
    batch: &crate::batch::PresignBatch,
    ttl: u32,
    now: DateTime<Utc>,
) -> Vec<vta_sdk::sealed_transfer::PresignedEntry> {
    let key = format!("{}{}", batch.prefix.as_str(), batch.object_key.as_str());
    let upload_id = batch.upload_id.as_ref().map(|u| u.as_str());
    let expires_at = rfc3339(now + Duration::seconds(i64::from(ttl)));
    batch
        .requests
        .iter()
        .enumerate()
        .map(|(i, op)| {
            let (method, query, headers) = operation_parts(op, upload_id);
            let (p, headers) = presign_with(s, secret, method, &key, &query, &headers, ttl, now);
            vta_sdk::sealed_transfer::PresignedEntry {
                index: i as u32,
                operation: crate::batch::operation_name(op).to_string(),
                method: p.method.to_string(),
                url: p.url.clone(),
                headers,
                expires_at: expires_at.clone(),
            }
        })
        .collect()
}

/// Remove a presigned URL's signature (and its credential scope) from text a
/// provider echoed back before it is shown to anyone.
fn redact(text: &str, url: &str) -> String {
    let mut out = text.replace(url, "<presigned-url>");
    if let Some(i) = out.find("X-Amz-Signature=") {
        out.truncate(i);
        out.push_str("<redacted>");
    }
    out.chars().take(2048).collect()
}

#[async_trait]
impl ExternalAuthDriver for S3StaticPresign {
    fn model(&self) -> &'static str {
        "s3-static-presign"
    }

    fn brokered(&self) -> bool {
        true
    }

    fn holds_secret(&self) -> bool {
        true
    }

    fn takes_presign(&self) -> bool {
        true
    }

    fn validate_settings(&self, v: &Value) -> Result<(), SettingsError> {
        settings(v).map(|_| ())
    }

    /// The store's own host — the one the probe dials. Issuance itself needs
    /// none: the consumer uses the URL.
    fn egress_hosts(&self, v: &Value) -> Vec<String> {
        settings(v)
            .ok()
            .and_then(|s| {
                let h = s.endpoint.host_str()?.to_ascii_lowercase();
                Some(if s.path_style {
                    h
                } else {
                    format!("{}.{h}", s.bucket)
                })
            })
            .into_iter()
            .collect()
    }

    fn setup(&self, account: &AccountRecord) -> Value {
        let bucket = account
            .settings
            .get("bucket")
            .and_then(Value::as_str)
            .unwrap_or("<bucket>");
        // The ceiling is the union of every binding's prefixes, so the key's
        // policy at the store is no wider than what the custodian will presign.
        let mut prefixes: Vec<String> = account
            .bindings
            .iter()
            .filter_map(|b| b.scope_ceiling.as_ref())
            .flat_map(|c| c.prefixes.iter().cloned())
            .collect();
        prefixes.sort();
        prefixes.dedup();
        if prefixes.is_empty() {
            prefixes.push("rooms/".into());
        }
        let resources: Vec<String> = prefixes
            .iter()
            .map(|p| format!("arn:aws:s3:::{bucket}/{p}*"))
            .collect();
        let policy = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                // Multipart writes are PutObject; ListParts and AbortMultipartUpload are
                // their own actions (`external/credentials/issue/0.2`, direct uploads).
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:DeleteObject",
                    "s3:ListMultipartUploadParts",
                    "s3:AbortMultipartUpload",
                ],
                "Resource": resources,
            }],
        });
        // For a browser moving a room's file straight to or from the bucket (a VTC's
        // `rooms/blobs/*/0.2` direct mode): the presigned requests are cross-origin, a
        // ranged GET and a part PUT carrying its signed checksum are both preflighted.
        // The origins are the operator's to fill in.
        let cors = json!({
            "CORSRules": [{
                "AllowedOrigins": ["https://<origin of the community's portal or console>"],
                "AllowedMethods": ["GET", "PUT"],
                "AllowedHeaders": ["Range", "Content-Length", "x-amz-checksum-sha256"],
                "ExposeHeaders": ["Content-Length", "Content-Range", "ETag"],
                "MaxAgeSeconds": 300,
            }],
        });
        // A direct upload the host never completes or aborts (it crashed, or lost
        // the upload id) keeps its parts, and bills for them, until it is aborted.
        // The host's own sweep aborts what it knows of; this rule is the backstop.
        let lifecycle = json!({
            "Rules": [{
                "ID": "abort-incomplete-room-uploads",
                "Status": "Enabled",
                "Filter": { "Prefix": prefixes.first().cloned().unwrap_or_else(|| "rooms/".into()) },
                "AbortIncompleteMultipartUpload": { "DaysAfterInitiation": 2 },
            }],
        });
        json!({
            "model": "s3-static-presign",
            "artifacts": [{
                "name": "permissions-policy.json",
                "mediaType": "application/json",
                "content": serde_json::to_string_pretty(&policy).unwrap_or_default(),
            }, {
                "name": "bucket-cors.json",
                "mediaType": "application/json",
                "content": serde_json::to_string_pretty(&cors).unwrap_or_default(),
            }, {
                "name": "bucket-lifecycle.json",
                "mediaType": "application/json",
                "content": serde_json::to_string_pretty(&lifecycle).unwrap_or_default(),
            }],
            "steps": [
                {"description": format!(
                    "Create an access key at the store scoped to bucket {bucket}, allowing only \
                     PutObject, GetObject, DeleteObject, ListMultipartUploadParts and \
                     AbortMultipartUpload on the prefixes in permissions-policy.json: no \
                     listing, no bucket or policy actions, no other bucket. (On R2 and B2, an API token restricted to this bucket with object \
                     read and write; on MinIO, a user with this policy attached.)"
                )},
                {"description": "Seal the secret access key in your client to this VTA and set it with \
                    external/accounts/secret/set. Do not paste it anywhere else: the access key \
                    id is the only half that belongs in the account's settings."},
                {"description": "Run external/accounts/probe. It writes, reads and deletes one canary \
                    object under the narrowest bound prefix (or the settings' probePrefix before \
                    anything is bound), so the key must allow exactly that. Only a probe that is \
                    ok and complete makes the account usable."},
                {"description": "Bind each consumer with the actions put, get and delete: put \
                    writes (multipart included), get reads and checks what was written, \
                    delete removes files and aborts an abandoned upload."},
                {"description": "Recommended: set bucket-lifecycle.json as the bucket's lifecycle \
                    configuration (`aws s3api put-bucket-lifecycle-configuration --bucket \
                    <bucket> --lifecycle-configuration file://bucket-lifecycle.json`), so a \
                    multipart upload nobody completes or aborts is reclaimed by the store."},
                {"description": "Optional, for browsers that move files straight to or from the \
                    bucket (a VTC's direct transfers): set bucket-cors.json as the bucket's CORS \
                    configuration, with AllowedOrigins replaced by the origins your members' \
                    browsers load the portal from (`aws s3api put-bucket-cors --bucket <bucket> \
                    --cors-configuration file://bucket-cors.json`; on R2, the bucket's CORS \
                    policy). Without it a browser must ask for a proxied transfer; \
                    non-browser clients need nothing."},
            ],
        })
    }

    async fn issue(&self, req: IssueRequest<'_>) -> Result<Issued, DriverError> {
        let s = settings(&req.account.settings).map_err(|e| DriverError::Internal(e.why))?;
        let Some(secret) = req.secret else {
            return Err(DriverError::SetupRequired(
                "the account's secret has not been set (external/accounts/secret/set)".into(),
            ));
        };
        let action = req.scope.actions.first().map(String::as_str).unwrap_or("");
        let method = method_for(action)
            .ok_or_else(|| DriverError::Internal(format!("unknown action {action:?}")))?;
        let (Some(prefix), Some(object)) =
            (req.scope.prefix.as_deref(), req.scope.object_key.as_deref())
        else {
            return Err(DriverError::Internal("scope was not checked".into()));
        };
        let key = format!("{prefix}{object}");
        let p = presign(&s, secret, method, &key, req.ttl_seconds, req.now);
        let expires_at = req.now + Duration::seconds(i64::from(req.ttl_seconds));
        Ok(Issued {
            credential: ExternalCredentialPayload::PresignedRequest {
                method: p.method.to_string(),
                url: p.url,
                headers: Default::default(),
                expires_at: rfc3339(expires_at),
                provider_request_id: None,
            },
            expires_at,
        })
    }

    async fn issue_batch(&self, req: BatchIssueRequest<'_>) -> Result<Issued, DriverError> {
        let s = settings(&req.account.settings).map_err(|e| DriverError::Internal(e.why))?;
        let Some(secret) = req.secret else {
            return Err(DriverError::SetupRequired(
                "the account's secret has not been set (external/accounts/secret/set)".into(),
            ));
        };
        let requests = presign_batch(&s, secret, req.batch, req.ttl_seconds, req.now);
        let expires_at = req.now + Duration::seconds(i64::from(req.ttl_seconds));
        Ok(Issued {
            credential: ExternalCredentialPayload::PresignedRequests {
                requests,
                expires_at: rfc3339(expires_at),
            },
            expires_at,
        })
    }

    async fn probe(
        &self,
        account: &AccountRecord,
        secret: Option<&str>,
        http: &reqwest::Client,
        now: DateTime<Utc>,
    ) -> Value {
        let mut steps: Vec<Value> = Vec::new();
        // `complete` is true only when the canary steps ran: put, get and
        // delete, the account exercised end to end.
        let report = |steps: Vec<Value>| {
            let ok = !steps.is_empty() && steps.iter().all(|s| s["ok"] == true);
            let complete = steps.iter().any(|s| s["step"] == "delete");
            json!({ "at": rfc3339(now), "ok": ok, "complete": complete, "steps": steps })
        };

        // sign: build the three presigned requests.
        let started = std::time::Instant::now();
        let signed = (|| {
            let s = settings(&account.settings).map_err(|e| format!("{}: {}", e.member, e.why))?;
            let secret = secret.ok_or("the account's secret has not been set")?;
            // The narrowest bound prefix: the canary goes where the tightest
            // binding can reach, so a key scoped to it passes. With no
            // bindings, the settings' `probePrefix`.
            let prefix = account
                .bindings
                .iter()
                .filter_map(|b| b.scope_ceiling.as_ref())
                .flat_map(|c| c.prefixes.iter())
                .max_by_key(|p| p.len())
                .cloned()
                .or_else(|| s.probe_prefix.clone());
            let key = format!(
                "{}vta-probe-{}",
                prefix.as_deref().unwrap_or("vta-probe/"),
                now.timestamp()
            );
            Ok::<_, String>((
                prefix.is_some(),
                [("put", "PUT"), ("get", "GET"), ("delete", "DELETE")]
                    .map(|(step, m)| (step, presign(&s, secret, m, &key, 120, now))),
            ))
        })();
        let presigned = match signed {
            Ok((bound, p)) => {
                steps.push(json!({ "step": "sign", "ok": true, "durationMs": started.elapsed().as_millis() as u64 }));
                // With no binding and no `probePrefix` there is nowhere the
                // key is meant to reach, so nothing is written and the report
                // is `complete: false`.
                if !bound {
                    return report(steps);
                }
                p
            }
            Err(e) => {
                steps.push(json!({ "step": "sign", "ok": false, "providerError": e }));
                return report(steps);
            }
        };

        // put, get, delete: each must succeed, and the first failure ends it.
        let body = b"vta external account probe".to_vec();
        for (step, p) in presigned {
            let started = std::time::Instant::now();
            let mut rb = match p.method {
                "PUT" => http.put(&p.url).body(body.clone()),
                "GET" => http.get(&p.url),
                _ => http.delete(&p.url),
            };
            rb = rb.timeout(std::time::Duration::from_secs(15));
            let outcome = rb.send().await;
            let ms = started.elapsed().as_millis() as u64;
            match outcome {
                Ok(resp) => {
                    let status = resp.status();
                    let request_id = resp
                        .headers()
                        .get("x-amz-request-id")
                        .or_else(|| resp.headers().get("cf-ray"))
                        .and_then(|v| v.to_str().ok())
                        .filter(|v| v.bytes().all(|b| (b'!'..=b'~').contains(&b)))
                        .map(|v| v.chars().take(256).collect::<String>());
                    let mut entry =
                        json!({ "step": step, "ok": status.is_success(), "durationMs": ms });
                    if let Some(id) = request_id {
                        entry["providerRequestId"] = Value::String(id);
                    }
                    if !status.is_success() {
                        let text = vta_sdk::http::read_body_capped(resp, 4096)
                            .await
                            .map(|b| String::from_utf8_lossy(&b).into_owned())
                            .unwrap_or_default();
                        entry["providerError"] =
                            Value::String(redact(&format!("HTTP {status}: {text}"), &p.url));
                        steps.push(entry);
                        return report(steps);
                    }
                    steps.push(entry);
                }
                Err(e) => {
                    steps.push(json!({
                        "step": step, "ok": false, "durationMs": ms,
                        "providerError": redact(&e.to_string(), &p.url),
                    }));
                    return report(steps);
                }
            }
        }
        report(steps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn r2() -> Settings {
        settings(&json!({
            "model": "s3-static-presign",
            "endpoint": "https://acct.r2.cloudflarestorage.com",
            "region": "auto",
            "bucket": "rooms-eu",
            "accessKeyId": "AKIDEXAMPLE",
        }))
        .unwrap()
    }

    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const SUM: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

    /// Recompute a presigned request's signature from what a verifier sees — the URL
    /// and the headers sent — as storage does: the query minus the signature, the
    /// headers `X-Amz-SignedHeaders` names, `UNSIGNED-PAYLOAD`.
    fn verifies(method: &str, url: &str, sent: &BTreeMap<String, String>) -> bool {
        let u = Url::parse(url).unwrap();
        let mut sig = String::new();
        let mut q: Vec<(String, String)> = Vec::new();
        let mut signed_names = String::new();
        let mut date = String::new();
        for (k, v) in u.query_pairs() {
            match k.as_ref() {
                "X-Amz-Signature" => sig = v.to_string(),
                _ => {
                    if k == "X-Amz-SignedHeaders" {
                        signed_names = v.to_string();
                    }
                    if k == "X-Amz-Date" {
                        date = v.to_string();
                    }
                    q.push((uri_encode(&k, false), uri_encode(&v, false)));
                }
            }
        }
        q.sort();
        let cq = q
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let host = u.host_str().unwrap().to_string();
        let lower: BTreeMap<String, String> = sent
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
            .collect();
        let mut block = String::new();
        for name in signed_names.split(';') {
            let v = if name == "host" {
                Some(&host)
            } else {
                lower.get(name)
            };
            let Some(v) = v else { return false };
            block.push_str(&format!("{name}:{v}\n"));
        }
        let creq = format!(
            "{method}\n{}\n{cq}\n{block}\n{signed_names}\nUNSIGNED-PAYLOAD",
            u.path()
        );
        let scope = format!("{}/auto/s3/aws4_request", &date[..8]);
        let sts = format!(
            "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
            hex::encode(Sha256::digest(creq.as_bytes()))
        );
        let k = hmac(
            &hmac(
                &hmac(
                    &hmac(format!("AWS4{SECRET}").as_bytes(), &date.as_bytes()[..8]),
                    b"auto",
                ),
                b"s3",
            ),
            b"aws4_request",
        );
        hex::encode(hmac(&k, sts.as_bytes())) == sig
    }

    fn batch(v: Value) -> crate::batch::PresignBatch {
        serde_json::from_value(v).unwrap()
    }

    /// Every operation is signed with exactly the table's method, query and headers
    /// (`issue/0.2` item 10): the signature covers them, any other value fails, and
    /// nothing else is signed.
    #[test]
    fn a_batch_signs_exactly_the_specifications_headers_and_query() {
        let now = Utc::now();
        let mp = batch(json!({
            "prefix": "rooms/abc/", "objectKey": "zBlob-u1", "uploadId": "up/load+id=",
            "requests": [
                {"operation": "upload-part", "partNumber": 3, "contentLength": 5242880, "checksumSha256": SUM},
                {"operation": "list-parts", "partNumberMarker": 1000},
                {"operation": "complete-multipart", "contentLength": 15728640},
                {"operation": "abort-multipart"},
            ]
        }));
        let set = presign_batch(&r2(), SECRET, &mp, 300, now);
        let one = batch(json!({
            "prefix": "rooms/abc/", "objectKey": "zBlob-u1",
            "requests": [
                {"operation": "put", "contentLength": 300000, "checksumSha256": SUM},
                {"operation": "create-multipart"},
                {"operation": "head"}, {"operation": "get"}, {"operation": "delete"},
            ]
        }));
        let set2 = presign_batch(&r2(), SECRET, &one, 300, now);
        let expect: &[(&str, &str, &[&str], &[&str])] = &[
            // operation, method, signed headers (beside host), non-auth query keys
            (
                "upload-part",
                "PUT",
                &["content-length", "x-amz-checksum-sha256"],
                &["partNumber", "uploadId"],
            ),
            (
                "list-parts",
                "GET",
                &[],
                &["max-parts", "part-number-marker", "uploadId"],
            ),
            (
                "complete-multipart",
                "POST",
                &["x-amz-mp-object-size"],
                &["uploadId"],
            ),
            ("abort-multipart", "DELETE", &[], &["uploadId"]),
            (
                "put",
                "PUT",
                &["content-length", "x-amz-checksum-sha256"],
                &[],
            ),
            (
                "create-multipart",
                "POST",
                &["x-amz-checksum-algorithm"],
                &["uploads"],
            ),
            ("head", "HEAD", &["x-amz-checksum-mode"], &[]),
            ("get", "GET", &[], &[]),
            ("delete", "DELETE", &[], &[]),
        ];
        for (entry, (op, method, hdrs, query)) in set.iter().chain(set2.iter()).zip(expect) {
            assert_eq!(entry.operation, *op);
            assert_eq!(entry.method, *method);
            let u = Url::parse(&entry.url).unwrap();
            assert!(
                u.path().ends_with("/rooms/abc/zBlob-u1"),
                "{op}: one object"
            );
            let signed: Vec<String> = u
                .query_pairs()
                .find(|(k, _)| k == "X-Amz-SignedHeaders")
                .unwrap()
                .1
                .split(';')
                .map(str::to_string)
                .collect();
            let mut want: Vec<String> = hdrs.iter().map(|h| h.to_string()).collect();
            want.push("host".into());
            want.sort();
            assert_eq!(signed, want, "{op}: signed headers");
            let mut extra: Vec<String> = u
                .query_pairs()
                .map(|(k, _)| k.to_string())
                .filter(|k| !k.starts_with("X-Amz-"))
                .collect();
            extra.sort();
            assert_eq!(extra, query.to_vec(), "{op}: signed query");
            let returned: Vec<String> = entry
                .headers
                .keys()
                .map(|k| k.to_ascii_lowercase())
                .collect();
            assert_eq!(
                returned.len(),
                hdrs.len(),
                "{op}: every signed header returned"
            );
            assert!(
                verifies(method, &entry.url, &entry.headers),
                "{op}: verifies as sent"
            );
            for name in entry.headers.keys() {
                let mut tampered = entry.headers.clone();
                tampered.insert(name.clone(), "1".into());
                assert!(
                    !verifies(method, &entry.url, &tampered),
                    "{op}: {name} is covered"
                );
            }
            assert!(
                !verifies("PATCH", &entry.url, &entry.headers),
                "{op}: method is covered"
            );
        }
        // The upload id is percent-encoded into the signed query, not interpolated.
        assert!(set[0].url.contains("uploadId=up%2Fload%2Bid%3D"));
        assert!(set[0].url.contains("partNumber=3"));
        assert_eq!(set[0].headers["Content-Length"], "5242880");
        assert_eq!(set[2].headers["x-amz-mp-object-size"], "15728640");
        // A changed query value no longer verifies.
        let moved = set[0].url.replace("partNumber=3", "partNumber=4");
        assert!(!verifies("PUT", &moved, &set[0].headers));
    }

    /// The worked example in the S3 API reference, "Authenticating Requests:
    /// Using Query Parameters (AWS Signature Version 4)": a presigned GET of
    /// `test.txt` in `examplebucket`, 24 hours, us-east-1, 2013-05-24.
    #[test]
    fn matches_the_aws_presigned_url_example() {
        let s = settings(&json!({
            "model": "s3-static-presign",
            "endpoint": "https://s3.amazonaws.com",
            "region": "us-east-1",
            "bucket": "examplebucket",
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
        }))
        .unwrap();
        let now = DateTime::parse_from_rfc3339("2013-05-24T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let p = presign(
            &s,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "GET",
            "test.txt",
            86400,
            now,
        );
        assert_eq!(
            p.url,
            "https://examplebucket.s3.amazonaws.com/test.txt\
             ?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
             &X-Amz-Date=20130524T000000Z\
             &X-Amz-Expires=86400\
             &X-Amz-SignedHeaders=host\
             &X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
        );
    }

    #[test]
    fn path_style_puts_the_bucket_in_the_path() {
        let s = settings(&json!({
            "model": "s3-static-presign",
            "endpoint": "https://minio.example.org:9000",
            "region": "us-east-1",
            "bucket": "rooms",
            "pathStyle": true,
            "accessKeyId": "MINIO",
        }))
        .unwrap();
        let p = presign(&s, "k", "PUT", "rooms/ab/blob", 60, Utc::now());
        assert!(
            p.url
                .starts_with("https://minio.example.org:9000/rooms/rooms/ab/blob?"),
            "{}",
            p.url
        );
        assert_eq!(p.method, "PUT");
    }

    #[test]
    fn settings_that_could_smuggle_anything_are_refused_naming_the_member() {
        for (k, v) in [
            ("endpoint", "http://s3.example.org"),
            ("endpoint", "https://s3.example.org/path"),
            ("endpoint", "https://user:pw@s3.example.org"),
            ("bucket", "Bad_Bucket"),
            ("region", "us east"),
            ("accessKeyId", "AKID/../"),
        ] {
            let mut v0 = json!({
                "model": "s3-static-presign", "endpoint": "https://s3.example.org",
                "region": "auto", "bucket": "rooms", "accessKeyId": "AKID",
            });
            v0[k] = Value::String(v.into());
            let err = settings(&v0)
                .err()
                .unwrap_or_else(|| panic!("{k}={v} accepted"));
            assert_eq!(err.member, k);
        }
    }

    #[test]
    fn a_provider_error_never_carries_the_signature() {
        let url = "https://b.s3.example.org/k?X-Amz-Signature=abc";
        let r = redact(&format!("denied for {url}"), url);
        assert!(!r.contains("abc"), "{r}");
        let r = redact("echo X-Amz-Signature=deadbeef trailing", url);
        assert!(!r.contains("deadbeef"), "{r}");
    }

    /// With no binding and no `probePrefix` nothing is written: the probe stops
    /// after `sign`, ok but not complete, so it cannot make the account usable.
    #[tokio::test]
    async fn an_unbound_probe_without_a_probe_prefix_is_not_complete() {
        let now = Utc::now();
        let account = AccountRecord {
            id: "r2".into(),
            label: "R2".into(),
            context: "c".into(),
            settings: json!({
                "model": "s3-static-presign", "endpoint": "https://s3.example.invalid",
                "region": "auto", "bucket": "rooms", "accessKeyId": "AKID",
            }),
            state: crate::model::AccountState::Active,
            public_material: None,
            secret: None,
            bindings: vec![],
            provider_setup_required: true,
            last_probe: None,
            created_at: now,
            updated_at: now,
        };
        let report = S3StaticPresign
            .probe(&account, Some("secret"), crate::driver::probe_client(), now)
            .await;
        assert_eq!(report["ok"], true, "{report}");
        assert_eq!(report["complete"], false, "{report}");
        assert_eq!(report["steps"].as_array().unwrap().len(), 1);
    }
}
