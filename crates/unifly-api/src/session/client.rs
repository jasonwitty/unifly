// Session API HTTP client
//
// Wraps `reqwest::Client` with UniFi-specific URL construction, envelope
// unwrapping, and platform-aware path prefixing. All endpoint modules
// (devices, clients, etc.) are implemented as inherent methods via
// separate files to keep this module focused on transport mechanics.

use std::sync::{Arc, RwLock};

use reqwest::cookie::{CookieStore, Jar};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::{debug, trace, warn};
use url::Url;

use crate::auth::ControllerPlatform;
use crate::error::Error;
use crate::session::models::SessionResponse;
use crate::transport::TransportConfig;

/// UniFi OS wraps some errors as `{"error":{"code":N,"message":"..."}}` with HTTP 200.
#[derive(serde::Deserialize)]
struct UnifiOsError {
    error: Option<UnifiOsErrorInner>,
}

#[derive(serde::Deserialize)]
struct UnifiOsErrorInner {
    code: u16,
    message: Option<String>,
}

/// How this session client authenticates with the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuth {
    /// Real session cookie from username/password login.
    Cookie,
    /// API key passed via `X-API-KEY` header (no session cookie).
    /// Some session endpoints (e.g. `stat/event`) are unavailable.
    ApiKey,
}

/// Raw HTTP client for the UniFi controller's session API.
///
/// Handles the `{ data: [], meta: { rc, msg } }` envelope, site-scoped
/// URL construction, and platform-aware path prefixing. All methods return
/// unwrapped `data` payloads -- the envelope is stripped before the caller
/// sees it.
pub struct SessionClient {
    http: reqwest::Client,
    base_url: Url,
    site: String,
    platform: ControllerPlatform,
    auth: SessionAuth,
    /// CSRF token for UniFi OS. Required on all POST/PUT/DELETE requests
    /// through the `/proxy/network/` path. Captured from login response
    /// headers and rotated via `X-Updated-CSRF-Token`.
    csrf_token: RwLock<Option<String>>,
    /// Cookie jar reference for extracting session cookies (e.g. for WebSocket auth).
    cookie_jar: Option<Arc<Jar>>,
}

/// First ~200 bytes of a response body for error messages, never panicking
/// on a multi-byte character boundary.
fn body_preview(body: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(&body[..body.len().min(200)])
}

impl SessionClient {
    /// Create a new session client from a `TransportConfig`.
    ///
    /// If the config doesn't already include a cookie jar, one is created
    /// automatically (session auth requires cookies). The `base_url` should be
    /// the controller root (e.g. `https://192.168.1.1` for UniFi OS or
    /// `https://controller:8443` for standalone).
    pub fn new(
        base_url: Url,
        site: String,
        platform: ControllerPlatform,
        transport: &TransportConfig,
    ) -> Result<Self, Error> {
        let config = if transport.cookie_jar.is_some() {
            transport.clone()
        } else {
            transport.clone().with_cookie_jar()
        };
        let cookie_jar = config.cookie_jar.clone();
        let http = config.build_client()?;
        Ok(Self {
            http,
            base_url,
            site,
            platform,
            auth: SessionAuth::Cookie,
            csrf_token: RwLock::new(None),
            cookie_jar,
        })
    }

    /// Create a session client with a pre-built `reqwest::Client`.
    ///
    /// Use this when you already have a client with a session cookie in its
    /// jar (e.g. after authenticating via a shared client).
    pub fn with_client(
        http: reqwest::Client,
        base_url: Url,
        site: String,
        platform: ControllerPlatform,
        auth: SessionAuth,
    ) -> Self {
        Self {
            http,
            base_url,
            site,
            platform,
            auth,
            csrf_token: RwLock::new(None),
            cookie_jar: None,
        }
    }

    /// The authentication method used by this client.
    pub fn auth(&self) -> SessionAuth {
        self.auth
    }

    /// The current site identifier.
    pub fn site(&self) -> &str {
        &self.site
    }

    /// The underlying HTTP client (for auth flows that need direct access).
    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// The controller base URL.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// The detected controller platform.
    pub fn platform(&self) -> ControllerPlatform {
        self.platform
    }

    /// Extract the session cookie header value for WebSocket auth.
    ///
    /// Returns the `Cookie` header string (e.g. `"TOKEN=abc123"`) if a
    /// cookie jar is available and contains cookies for the controller URL.
    pub fn cookie_header(&self) -> Option<String> {
        let jar = self.cookie_jar.as_ref()?;
        let cookies = jar.cookies(&self.base_url)?;
        cookies.to_str().ok().map(String::from)
    }

    // ── Cookie injection (for MFA flow) ───────────────────────────────

    /// Inject a `Set-Cookie` header value into the client's cookie jar.
    ///
    /// Used by the MFA flow to inject the `UBIC_2FA` cookie before retrying
    /// login with the TOTP token.
    pub(crate) fn add_cookie(&self, set_cookie_value: &str, url: &Url) -> Result<(), Error> {
        let jar = self
            .cookie_jar
            .as_ref()
            .ok_or_else(|| Error::Authentication {
                message: "no cookie jar available for MFA flow".into(),
            })?;
        let header_value: reqwest::header::HeaderValue =
            set_cookie_value
                .parse()
                .map_err(|_| Error::Authentication {
                    message: "failed to parse MFA cookie value".into(),
                })?;
        jar.set_cookies(&mut std::iter::once(&header_value), url);
        Ok(())
    }

    // ── CSRF token management ─────────────────────────────────────────

    /// Read the current CSRF token value (for session caching).
    pub(crate) fn csrf_token_value(&self) -> Option<String> {
        self.csrf_token.read().expect("CSRF lock poisoned").clone()
    }

    /// Store a CSRF token (captured from login response headers).
    pub(crate) fn set_csrf_token(&self, token: String) {
        debug!("storing CSRF token");
        *self.csrf_token.write().expect("CSRF lock poisoned") = Some(token);
    }

    /// Update CSRF token if the response contains a rotated value.
    fn update_csrf_from_response(&self, headers: &reqwest::header::HeaderMap) {
        // UniFi OS may rotate tokens — prefer the updated one.
        let new_token = headers
            .get("X-Updated-CSRF-Token")
            .or_else(|| headers.get("x-csrf-token"))
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        if let Some(token) = new_token {
            trace!("CSRF token rotated");
            *self.csrf_token.write().expect("CSRF lock poisoned") = Some(token);
        }
    }

    /// Apply the stored CSRF token to a request builder.
    fn apply_csrf(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let guard = self.csrf_token.read().expect("CSRF lock poisoned");
        match guard.as_deref() {
            Some(token) => builder.header("X-CSRF-Token", token),
            None => builder,
        }
    }

    /// Classify a session 401 based on the active auth strategy.
    ///
    /// Cookie-backed session clients surface 401s as an expired session.
    /// API-key clients surface the same status as a rejected key.
    fn unauthorized_error(&self) -> Error {
        match self.auth {
            SessionAuth::Cookie => Error::SessionExpired,
            SessionAuth::ApiKey => Error::InvalidApiKey,
        }
    }

    // ── URL builders ─────────────────────────────────────────────────

    /// Build a full URL for a controller-level API path.
    ///
    /// Applies the platform-specific session prefix, then appends `/api/{path}`.
    /// For example, on UniFi OS: `https://host/proxy/network/api/{path}`
    pub(crate) fn api_url(&self, path: &str) -> Url {
        let prefix = self.platform.session_prefix().unwrap_or("");
        let base = self.base_url.as_str().trim_end_matches('/');
        let prefix = prefix.trim_end_matches('/');
        let full = format!("{base}{prefix}/api/{path}");
        Url::parse(&full).expect("invalid API URL")
    }

    /// Build a site-scoped URL: `{base}{prefix}/api/s/{site}/{path}`
    ///
    /// Most session endpoints are site-scoped: stat/device, cmd/devmgr, etc.
    pub(crate) fn site_url(&self, path: &str) -> Url {
        let prefix = self.platform.session_prefix().unwrap_or("");
        let base = self.base_url.as_str().trim_end_matches('/');
        let prefix = prefix.trim_end_matches('/');
        let full = format!("{base}{prefix}/api/s/{}/{path}", self.site);
        Url::parse(&full).expect("invalid site URL")
    }

    /// Build a v2 site-scoped URL: `{base}{prefix}/v2/api/site/{site}/{path}`
    ///
    /// Used by newer endpoints (Network Application 9+) that use the v2 path
    /// format, e.g. traffic-flow-latest-statistics.
    pub(crate) fn site_url_v2(&self, path: &str) -> Url {
        let prefix = self.platform.session_prefix().unwrap_or("");
        let base = self.base_url.as_str().trim_end_matches('/');
        let prefix = prefix.trim_end_matches('/');
        let full = format!("{base}{prefix}/v2/api/site/{}/{path}", self.site);
        Url::parse(&full).expect("invalid v2 site URL")
    }

    // ── Request helpers ──────────────────────────────────────────────

    /// Send a GET request and unwrap the session envelope.
    pub(crate) async fn get<T: DeserializeOwned>(&self, url: Url) -> Result<Vec<T>, Error> {
        debug!("GET {}", url);

        let resp = self.http.get(url).send().await.map_err(Error::Transport)?;

        self.parse_envelope(resp).await
    }

    /// Send a GET request and return the raw JSON response (no envelope unwrapping).
    ///
    /// Used for v2 API endpoints that return plain JSON instead of the
    /// session `{ meta, data }` envelope.
    pub(crate) async fn get_raw(&self, url: Url) -> Result<serde_json::Value, Error> {
        debug!("GET (raw) {}", url);

        let resp = self.http.get(url).send().await.map_err(Error::Transport)?;
        let status = resp.status();

        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(self.unauthorized_error());
        }
        if !status.is_success() {
            let body = resp.bytes().await.unwrap_or_default();
            return Err(Error::SessionApi {
                message: format!("HTTP {status}: {}", body_preview(&body)),
            });
        }

        let body = resp.bytes().await.map_err(Error::Transport)?;
        serde_json::from_slice(&body).map_err(|e| Error::Deserialization {
            message: format!("{e}"),
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }

    /// Send a POST request with JSON body and unwrap the session envelope.
    pub(crate) async fn post<T: DeserializeOwned>(
        &self,
        url: Url,
        body: &(impl Serialize + Sync),
    ) -> Result<Vec<T>, Error> {
        debug!("POST {}", url);

        let builder = self.apply_csrf(self.http.post(url).json(body));
        let resp = builder.send().await.map_err(Error::Transport)?;

        self.parse_envelope(resp).await
    }

    /// Send a PUT request with JSON body and unwrap the session envelope.
    #[allow(dead_code)]
    pub(crate) async fn put<T: DeserializeOwned>(
        &self,
        url: Url,
        body: &(impl Serialize + Sync),
    ) -> Result<Vec<T>, Error> {
        debug!("PUT {}", url);

        let builder = self.apply_csrf(self.http.put(url).json(body));
        let resp = builder.send().await.map_err(Error::Transport)?;

        self.parse_envelope(resp).await
    }

    /// Send a DELETE request and unwrap the session envelope.
    #[allow(dead_code)]
    pub(crate) async fn delete<T: DeserializeOwned>(&self, url: Url) -> Result<Vec<T>, Error> {
        debug!("DELETE {}", url);

        let builder = self.apply_csrf(self.http.delete(url));
        let resp = builder.send().await.map_err(Error::Transport)?;

        self.parse_envelope(resp).await
    }

    /// Send a raw GET to an arbitrary path (no envelope unwrapping).
    ///
    /// The `path` is appended directly after `{base}{prefix}/`.
    pub async fn raw_get(&self, path: &str) -> Result<serde_json::Value, Error> {
        let prefix = self.platform.session_prefix().unwrap_or("");
        let base = self.base_url.as_str().trim_end_matches('/');
        let prefix = prefix.trim_end_matches('/');
        let url = Url::parse(&format!("{base}{prefix}/{path}")).expect("invalid raw URL");
        self.get_raw(url).await
    }

    /// Send a raw POST to an arbitrary path (no envelope unwrapping).
    pub async fn raw_post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, Error> {
        let prefix = self.platform.session_prefix().unwrap_or("");
        let base = self.base_url.as_str().trim_end_matches('/');
        let prefix = prefix.trim_end_matches('/');
        let url = Url::parse(&format!("{base}{prefix}/{path}")).expect("invalid raw URL");
        debug!("POST (raw) {}", url);

        let builder = self.apply_csrf(self.http.post(url).json(body));
        let resp = builder.send().await.map_err(Error::Transport)?;
        let status = resp.status();

        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(self.unauthorized_error());
        }
        if !status.is_success() {
            let body = resp.bytes().await.unwrap_or_default();
            return Err(Error::SessionApi {
                message: format!("HTTP {status}: {}", body_preview(&body)),
            });
        }

        let body = resp.bytes().await.map_err(Error::Transport)?;
        serde_json::from_slice(&body).map_err(|e| Error::Deserialization {
            message: format!("{e}"),
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }

    /// Send a raw PUT to an arbitrary path (no envelope unwrapping).
    pub async fn raw_put(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, Error> {
        let prefix = self.platform.session_prefix().unwrap_or("");
        let base = self.base_url.as_str().trim_end_matches('/');
        let prefix = prefix.trim_end_matches('/');
        let url = Url::parse(&format!("{base}{prefix}/{path}")).expect("invalid raw URL");
        debug!("PUT (raw) {}", url);

        let builder = self.apply_csrf(self.http.put(url).json(body));
        let resp = builder.send().await.map_err(Error::Transport)?;
        let status = resp.status();

        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(self.unauthorized_error());
        }
        if !status.is_success() {
            let body = resp.bytes().await.unwrap_or_default();
            return Err(Error::SessionApi {
                message: format!("HTTP {status}: {}", body_preview(&body)),
            });
        }

        let body = resp.bytes().await.map_err(Error::Transport)?;
        serde_json::from_slice(&body).map_err(|e| Error::Deserialization {
            message: format!("{e}"),
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }

    /// Send a raw PATCH to an arbitrary path (no envelope unwrapping).
    pub async fn raw_patch(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, Error> {
        let prefix = self.platform.session_prefix().unwrap_or("");
        let base = self.base_url.as_str().trim_end_matches('/');
        let prefix = prefix.trim_end_matches('/');
        let url = Url::parse(&format!("{base}{prefix}/{path}")).expect("invalid raw URL");
        debug!("PATCH (raw) {}", url);

        let builder = self.apply_csrf(self.http.patch(url).json(body));
        let resp = builder.send().await.map_err(Error::Transport)?;
        let status = resp.status();

        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(self.unauthorized_error());
        }
        if !status.is_success() {
            let body = resp.bytes().await.unwrap_or_default();
            return Err(Error::SessionApi {
                message: format!("HTTP {status}: {}", body_preview(&body)),
            });
        }

        let body = resp.bytes().await.map_err(Error::Transport)?;
        serde_json::from_slice(&body).map_err(|e| Error::Deserialization {
            message: format!("{e}"),
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }

    /// Send a raw DELETE to an arbitrary path (no envelope unwrapping).
    pub async fn raw_delete(&self, path: &str) -> Result<(), Error> {
        let prefix = self.platform.session_prefix().unwrap_or("");
        let base = self.base_url.as_str().trim_end_matches('/');
        let prefix = prefix.trim_end_matches('/');
        let url = Url::parse(&format!("{base}{prefix}/{path}")).expect("invalid raw URL");
        debug!("DELETE (raw) {}", url);

        let builder = self.apply_csrf(self.http.delete(url));
        let resp = builder.send().await.map_err(Error::Transport)?;
        let status = resp.status();

        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(self.unauthorized_error());
        }
        if !status.is_success() {
            let body = resp.bytes().await.unwrap_or_default();
            return Err(Error::SessionApi {
                message: format!("HTTP {status}: {}", body_preview(&body)),
            });
        }

        Ok(())
    }

    /// Parse the `{ meta, data }` envelope, returning `data` on success
    /// or an `Error::SessionApi` if `meta.rc != "ok"`.
    ///
    /// Also handles UniFi OS error responses that use a different shape:
    /// `{"error": {"code": 403, "message": "..."}}` (returned with HTTP 200).
    async fn parse_envelope<T: DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> Result<Vec<T>, Error> {
        let status = resp.status();

        // Capture any CSRF token rotation before consuming the response.
        self.update_csrf_from_response(resp.headers());

        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(self.unauthorized_error());
        }

        if status == reqwest::StatusCode::FORBIDDEN {
            return Err(Error::SessionApi {
                message: "insufficient permissions (HTTP 403)".into(),
            });
        }

        if !status.is_success() {
            let body = resp.bytes().await.unwrap_or_default();
            return Err(Error::SessionApi {
                message: format!("HTTP {status}: {}", body_preview(&body)),
            });
        }

        let body = resp.bytes().await.map_err(Error::Transport)?;

        // UniFi OS sometimes returns `{"error":{"code":N,"message":"..."}}` with HTTP 200.
        if let Ok(wrapper) = serde_json::from_slice::<UnifiOsError>(&body)
            && let Some(err) = wrapper.error
        {
            let msg = err.message.unwrap_or_default();
            return Err(if err.code == 401 {
                if msg.is_empty() {
                    self.unauthorized_error()
                } else {
                    match self.unauthorized_error() {
                        Error::SessionExpired => Error::Authentication {
                            message: format!("session expired: {msg}"),
                        },
                        Error::InvalidApiKey => Error::Authentication {
                            message: format!("API key rejected: {msg}"),
                        },
                        other => other,
                    }
                }
            } else {
                Error::SessionApi {
                    message: format!("UniFi OS error {}: {msg}", err.code),
                }
            });
        }

        let envelope: SessionResponse<serde_json::Value> =
            serde_json::from_slice(&body).map_err(|e| {
                let preview = body_preview(&body);
                Error::Deserialization {
                    message: format!("{e} (body preview: {preview:?})"),
                    body: String::from_utf8_lossy(&body).into_owned(),
                }
            })?;

        if envelope.meta.rc != "ok" {
            return Err(Error::SessionApi {
                message: envelope
                    .meta
                    .msg
                    .unwrap_or_else(|| format!("rc={}", envelope.meta.rc)),
            });
        }

        // Decode per record so one unexpected field shape (UniFi is fond of
        // `"auto"` where a number is documented) drops that record with a
        // warning instead of blanking the whole collection. If every record
        // fails, surface the first error so single-item lookups still report
        // a real deserialization problem rather than "not found".
        let total = envelope.data.len();
        let mut items = Vec::with_capacity(total);
        let mut first_error = None;
        for (index, value) in envelope.data.into_iter().enumerate() {
            match serde_json::from_value::<T>(value) {
                Ok(item) => items.push(item),
                Err(error) => {
                    warn!(index, %error, "skipping session record that failed to decode");
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        if items.is_empty()
            && let Some(error) = first_error
        {
            return Err(Error::Deserialization {
                message: format!("{error} (all {total} records failed to decode)"),
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }

        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::{SessionAuth, SessionClient};
    use crate::{ControllerPlatform, Error};

    fn client(auth: SessionAuth) -> SessionClient {
        crate::transport::ensure_crypto_provider();
        SessionClient::with_client(
            reqwest::Client::new(),
            Url::parse("https://controller.example").expect("valid test URL"),
            "default".into(),
            ControllerPlatform::ClassicController,
            auth,
        )
    }

    #[test]
    fn unauthorized_cookie_client_reports_session_expired() {
        assert!(matches!(
            client(SessionAuth::Cookie).unauthorized_error(),
            Error::SessionExpired
        ));
    }

    #[test]
    fn unauthorized_api_key_client_reports_invalid_api_key() {
        assert!(matches!(
            client(SessionAuth::ApiKey).unauthorized_error(),
            Error::InvalidApiKey
        ));
    }
}
