//! The `MockVta` test-harness helper: a real, listening VTA on a random
//! loopback port that any HTTP client can drive — verified here by hitting the
//! unauthenticated `GET /health` over the wire (raw TCP, no client dep).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use vta_service::test_support::MockVta;

/// Minimal HTTP/1.1 GET over a fresh TCP connection; returns the raw response.
async fn http_get(addr: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect to mock VTA");
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test]
async fn mock_vta_serves_health_over_http() {
    let mock = MockVta::start().await;
    let addr = mock
        .base_url()
        .strip_prefix("http://")
        .expect("base_url is http://")
        .to_string();

    let response = http_get(&addr, "/health").await;

    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200 from /health, got:\n{response}"
    );
    // The health handler returns a JSON status body.
    assert!(
        response.contains("status"),
        "expected a status body, got:\n{response}"
    );

    mock.shutdown().await;
}

#[tokio::test]
async fn mock_vta_gates_authenticated_routes() {
    let mock = MockVta::start().await;
    let addr = mock.base_url().strip_prefix("http://").unwrap().to_string();

    // An authenticated route without a token must not be served as 200 — the
    // mock is a real VTA, auth gates and all.
    let response = http_get(&addr, "/keys").await;
    assert!(
        !response.starts_with("HTTP/1.1 200"),
        "an unauthenticated /keys must not return 200, got:\n{}",
        response.lines().next().unwrap_or("")
    );

    mock.shutdown().await;
}
