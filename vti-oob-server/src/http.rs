//! Connection details the handlers cannot read from a document: the client
//! address, `User-Agent`, `Origin` and `Host`, and any cookies a successful
//! `redeem` asks the door to set. Only the HTTPS door supplies them
//! ([`HttpContext::scope`]), so `request` and `redeem` are HTTPS-only.

use std::net::IpAddr;
use std::sync::Arc;

/// What the HTTPS door knows about the connection a document arrived on, and
/// the cookies a handler asks it to set. Absent on every other transport.
#[derive(Debug)]
pub struct HttpContext {
    pub client_ip: IpAddr,
    pub user_agent: Option<String>,
    pub origin: Option<String>,
    pub host: Option<String>,
    set_cookies: std::sync::Mutex<Vec<String>>,
}

tokio::task_local! {
    static HTTP: Arc<HttpContext>;
}

impl HttpContext {
    pub fn new(
        client_ip: IpAddr,
        user_agent: Option<String>,
        origin: Option<String>,
        host: Option<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            client_ip,
            user_agent,
            origin,
            host,
            set_cookies: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// Run `fut` with `ctx` visible to the `auth/oob` handlers.
    pub async fn scope<F: std::future::Future>(ctx: Arc<Self>, fut: F) -> F::Output {
        HTTP.scope(ctx, fut).await
    }

    /// The context of the document being handled, if it came over HTTPS.
    pub fn current() -> Option<Arc<Self>> {
        HTTP.try_with(Arc::clone).ok()
    }

    /// Ask the door to send these `Set-Cookie` values with the response. A
    /// host that issues no cookies never calls it.
    pub fn set_cookies(&self, cookies: impl IntoIterator<Item = String>) {
        self.set_cookies
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend(cookies);
    }

    /// The cookies a handler asked for, once.
    pub fn take_cookies(&self) -> Vec<String> {
        std::mem::take(&mut *self.set_cookies.lock().unwrap_or_else(|p| p.into_inner()))
    }
}
