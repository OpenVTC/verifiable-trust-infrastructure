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

use crate::driver::{DriverError, ExternalAuthDriver, IssueRequest, Issued, SettingsError};
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
/// `expires_seconds` from `now`. Pure: no clock, no network.
fn presign(
    s: &Settings,
    secret: &str,
    method: &'static str,
    key: &str,
    expires_seconds: u32,
    now: DateTime<Utc>,
) -> Presigned {
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

    let mut query = [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string()),
        ("X-Amz-Credential", credential),
        ("X-Amz-Date", amz_date.clone()),
        ("X-Amz-Expires", expires_seconds.to_string()),
        ("X-Amz-SignedHeaders", "host".to_string()),
    ];
    query.sort_by(|a, b| a.0.cmp(b.0));
    let canonical_query = query
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, false), uri_encode(v, false)))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD"
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

    Presigned {
        method,
        url: format!(
            "{}://{host}{canonical_uri}?{canonical_query}&X-Amz-Signature={signature}",
            s.endpoint.scheme()
        ),
    }
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
                "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
                "Resource": resources,
            }],
        });
        json!({
            "model": "s3-static-presign",
            "artifacts": [{
                "name": "permissions-policy.json",
                "mediaType": "application/json",
                "content": serde_json::to_string_pretty(&policy).unwrap_or_default(),
            }],
            "steps": [
                {"description": format!(
                    "Create an access key at the store scoped to bucket {bucket}, allowing only \
                     PutObject, GetObject and DeleteObject on the prefixes in \
                     permissions-policy.json: no listing, no bucket or policy actions, no other \
                     bucket. (On R2 and B2, an API token restricted to this bucket with object \
                     read and write; on MinIO, a user with this policy attached.)"
                )},
                {"description": "Seal the secret access key in your client to this VTA and set it with \
                    external/accounts/secret/set. Do not paste it anywhere else: the access key \
                    id is the only half that belongs in the account's settings."},
                {"description": "Run external/accounts/probe. It writes, reads and deletes one canary \
                    object under the narrowest bound prefix (or the settings' probePrefix before \
                    anything is bound), so the key must allow exactly that. Only a probe that is \
                    ok and complete makes the account usable."},
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
