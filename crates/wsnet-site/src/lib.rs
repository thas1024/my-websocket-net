//! Decoy site and stage-uniform failure appearance (DESIGN.md §6.5, §9.1).
//!
//! §6.5 asks for a site that behaves like a site: a browsable home page, real
//! `robots.txt`/`sitemap.xml`/`favicon.ico`, and a genuine 404  "未知路径按正常
//! 站点状态码/Content-Type 处理，不统一伪造 HTTP 200".
//!
//! §9.1 then fixes what a failure must look like, *per protocol stage*:
//!
//! | stage | contract |
//! | --- | --- |
//! | HTTP not upgraded, SSE headers not sent | one deployment-appropriate HTML/JSON failure response; no auth/replay reason |
//! | WS upgraded, not yet authenticated | only valid WS public messages or a Close |
//! | SSE already started | only bounded public SSE events or a normal end |
//!
//! [`Site::failure`] takes only a [`FailureStage`], never a reason. That is the
//! point: §9.1 requires unauthenticated, expired, replayed, and binding failures
//! to be indistinguishable, so the API makes it impossible to leak the
//! distinction by accident rather than relying on every call site to be careful.
//!
//! The design is explicit that this is *not* an indistinguishability guarantee 
//! "这只是减少特定错误差异，不是不可区分性保证" — so nothing here is presented
//! as one.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use wsnet_limits::{FAILURE_MAX_BODY, MAX_SITE_RESOURCE};

/// A bounded HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// `Content-Type` value.
    pub content_type: &'static str,
    /// `Cache-Control` value.
    pub cache_control: &'static str,
    /// Response body; empty for `HEAD`.
    pub body: Vec<u8>,
    /// Full length of the entity, including the body omitted for `HEAD`.
    pub content_length: usize,
}

impl Response {
    /// Builds a response whose entity is the given body.
    pub fn new(status: u16, content_type: &'static str, cache_control: &'static str, body: Vec<u8>) -> Self {
        let content_length = body.len();
        Response {
            status,
            content_type,
            cache_control,
            body,
            content_length,
        }
    }

    /// Builds a response that must not be cached.
    ///
    /// §11 requires "所有业务/profile响应 no-store"; the carrier endpoints use
    /// this, while ordinary site assets may be cached normally.
    pub fn no_store(status: u16, content_type: &'static str, body: Vec<u8>) -> Self {
        Response::new(status, content_type, "no-store", body)
    }

    /// Builds a `text/html` response.
    pub fn html(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Response::new(status, "text/html; charset=utf-8", "no-cache", body.into())
    }

    /// The body to actually write, given the request method.
    pub fn body_for_method(&self, method: &str) -> &[u8] {
        if method.eq_ignore_ascii_case("HEAD") {
            &[]
        } else {
            &self.body
        }
    }
}

/// How a deployment chooses to look when it fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailureAppearance {
    /// Serve the site's own HTML 404 page, as §9.1's first option allows.
    #[default]
    Html,
    /// Serve a small JSON error body.
    Json,
}

/// The protocol stage a failure happened in (§9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureStage {
    /// HTTP request that was never upgraded and never started SSE.
    HttpPreAuth,
    /// WebSocket upgraded but authentication not yet successful.
    WsPreAuth,
    /// SSE response headers already sent.
    SseStarted,
}

/// A stage-appropriate failure action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageResponse {
    /// Write this HTTP response.
    Http(Response),
    /// Send a WebSocket Close with this status code (§9.1: 1000 normal, 1002
    /// protocol error).
    WsClose(u16),
    /// Send this bounded SSE comment/event and then end the stream.
    SseComment(Vec<u8>),
}

/// Errors from site construction.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SiteError {
    /// A configured resource exceeded its bound.
    #[error("site resource is {actual} bytes, limit is {limit}")]
    ResourceTooLarge {
        /// Observed size.
        actual: usize,
        /// Enforced bound.
        limit: usize,
    },
}

/// The deployment's public site plus its failure appearance.
#[derive(Debug, Clone)]
pub struct Site {
    home: Vec<u8>,
    not_found: Vec<u8>,
    robots: Vec<u8>,
    sitemap: Vec<u8>,
    favicon: Vec<u8>,
    /// Paths owned by the proxy, which the site must never serve.
    reserved: BTreeSet<String>,
    appearance: FailureAppearance,
}

/// Paths the carrier endpoints own (§11's nginx example).
pub const RESERVED_PATHS: [&str; 3] = ["/m", "/e", "/w"];

impl Default for Site {
    fn default() -> Self {
        Site::builtin()
    }
}

impl Site {
    /// The built-in decoy site.
    pub fn builtin() -> Self {
        Site {
            home: BUILTIN_HOME.to_vec(),
            not_found: BUILTIN_NOT_FOUND.to_vec(),
            robots: b"User-agent: *\nDisallow: /m\nDisallow: /e\nDisallow: /w\n".to_vec(),
            sitemap:
                b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n  <url><loc>/</loc></url>\n</urlset>\n"
                    .to_vec(),
            // A 1x1 transparent GIF is a valid, if boring, favicon.
            favicon: [
                0x47u8, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
                0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01,
                0x00, 0x3b,
            ]
            .to_vec(),
            reserved: RESERVED_PATHS.iter().map(|p| p.to_string()).collect(),
            appearance: FailureAppearance::Html,
        }
    }

    /// Replaces the home page, so deployments can inject their own content
    /// rather than sharing one fixed template (§6.5).
    pub fn with_home(mut self, html: impl Into<Vec<u8>>) -> Result<Self, SiteError> {
        let html = html.into();
        Self::check_size(html.len())?;
        self.home = html;
        Ok(self)
    }

    /// Replaces the 404 page.
    pub fn with_not_found(mut self, html: impl Into<Vec<u8>>) -> Result<Self, SiteError> {
        let html = html.into();
        Self::check_size(html.len())?;
        self.not_found = html;
        Ok(self)
    }

    /// Selects the failure appearance.
    pub fn with_appearance(mut self, appearance: FailureAppearance) -> Self {
        self.appearance = appearance;
        self
    }

    /// Reserves an additional path for the proxy.
    pub fn reserve_path(&mut self, path: impl Into<String>) {
        self.reserved.insert(path.into());
    }

    /// Whether the proxy owns this path.
    pub fn is_reserved(&self, path: &str) -> bool {
        self.reserved.contains(path)
    }

    fn check_size(actual: usize) -> Result<(), SiteError> {
        if actual > MAX_SITE_RESOURCE {
            return Err(SiteError::ResourceTooLarge {
                actual,
                limit: MAX_SITE_RESOURCE,
            });
        }
        Ok(())
    }

    /// Routes a public request by path.
    ///
    /// Returns `None` for a reserved path: the proxy handles it, and it must not
    /// be answered by the site even if it looks like an unknown page.
    ///
    /// There is no `method` parameter because routing does not depend on it. The
    /// returned [`Response`] always carries the full entity; the caller writes
    /// [`Response::body_for_method`], so HEAD handling lives in exactly one place
    /// instead of being applied here and then repeated by every transport.
    pub fn route(&self, path: &str) -> Option<Response> {
        let path = strip_query(path);
        if self.is_reserved(path) {
            return None;
        }
        Some(match path {
            "/" | "/index.html" => Response::html(200, self.home.clone()),
            "/robots.txt" => Response::new(
                200,
                "text/plain; charset=utf-8",
                "public, max-age=3600",
                self.robots.clone(),
            ),
            "/sitemap.xml" => Response::new(
                200,
                "application/xml",
                "public, max-age=3600",
                self.sitemap.clone(),
            ),
            "/favicon.ico" => Response::new(
                200,
                "image/gif",
                "public, max-age=86400",
                self.favicon.clone(),
            ),
            _ => Response::html(404, self.not_found.clone()),
        })
    }

    /// The stage-appropriate failure action.
    ///
    /// Deliberately takes no reason: see the module docs.
    pub fn failure(&self, stage: FailureStage) -> StageResponse {
        match stage {
            FailureStage::HttpPreAuth => StageResponse::Http(self.failure_response()),
            // §9.1: after an upgrade only WS frames or a Close are legal.
            FailureStage::WsPreAuth => StageResponse::WsClose(1000),
            // §9.1: after SSE headers only public bounded events are legal.
            FailureStage::SseStarted => StageResponse::SseComment(b": ok\n\n".to_vec()),
        }
    }

    fn failure_response(&self) -> Response {
        let body = match self.appearance {
            FailureAppearance::Html => self.not_found.clone(),
            FailureAppearance::Json => br#"{"error":"not_found"}"#.to_vec(),
        };
        // §9.2 caps the unauthenticated failure appearance at 16 KiB.
        let body = if body.len() > FAILURE_MAX_BODY {
            body[..FAILURE_MAX_BODY].to_vec()
        } else {
            body
        };
        let content_type = match self.appearance {
            FailureAppearance::Html => "text/html; charset=utf-8",
            FailureAppearance::Json => "application/json",
        };
        // A failure must not be cacheable, or a stale 404 would outlive the
        // condition that produced it.
        Response::new(404, content_type, "no-store", body)
    }
}

fn strip_query(path: &str) -> &str {
    match path.split_once('?') {
        Some((path, _)) => path,
        None => path,
    }
}

const BUILTIN_HOME: &[u8] = b"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Home</title>\n<link rel=\"stylesheet\" href=\"/style.css\">\n</head>\n<body>\n<h1>Home</h1>\n<p>This site is up.</p>\n</body>\n</html>\n";

const BUILTIN_NOT_FOUND: &[u8] = b"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Not Found</title>\n</head>\n<body>\n<h1>404 Not Found</h1>\n<p>The requested resource is not available.</p>\n</body>\n</html>\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_routes_the_expected_resources() {
        let site = Site::builtin();
        assert_eq!(site.route("/").unwrap().status, 200);
        assert_eq!(site.route("/index.html").unwrap().status, 200);
        assert_eq!(
            site.route("/robots.txt").unwrap().content_type,
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            site.route("/sitemap.xml").unwrap().content_type,
            "application/xml"
        );
        assert_eq!(
            site.route("/favicon.ico").unwrap().content_type,
            "image/gif"
        );
    }

    /// §6.5: unknown paths get a real 404, not a faked 200.
    #[test]
    fn unknown_paths_are_404_not_200() {
        let site = Site::builtin();
        let response = site.route("/no/such/page").unwrap();
        assert_eq!(response.status, 404);
        assert_eq!(response.content_type, "text/html; charset=utf-8");
    }

    /// Reserved carrier paths must never be answered by the site, even though
    /// they are not files on disk.
    #[test]
    fn reserved_paths_are_not_served_by_the_site() {
        let site = Site::builtin();
        for path in RESERVED_PATHS {
            assert!(site.is_reserved(path), "{path} should be reserved");
            assert!(
                site.route(path).is_none(),
                "{path} must be handled by the proxy, not the site"
            );
        }
        // A profile path can be reserved as well.
        let mut site = Site::builtin();
        site.reserve_path("/transport/page");
        assert!(site.route("/transport/page").is_none());
    }

    #[test]
    fn query_strings_do_not_change_routing() {
        let site = Site::builtin();
        assert_eq!(site.route("/robots.txt?v=2").unwrap().status, 200);
        assert_eq!(site.route("/nope?x=1").unwrap().status, 404);
    }

    #[test]
    fn head_omits_the_body_but_keeps_the_length() {
        let site = Site::builtin();
        let response = site.route("/").unwrap();
        // The entity is intact; only the writer decides what a HEAD sends.
        assert!(response.content_length > 0);
        assert_eq!(response.body.len(), response.content_length);
        assert!(response.body_for_method("HEAD").is_empty());
        assert_eq!(
            response.body_for_method("GET").len(),
            response.content_length
        );
    }

    /// §9.1: every pre-auth failure looks the same, because the API cannot
    /// express a reason.
    #[test]
    fn pre_auth_failures_are_identical_regardless_of_cause() {
        let site = Site::builtin();
        let first = site.failure(FailureStage::HttpPreAuth);
        // There is no way to ask for "expired" or "replayed" separately.
        for _ in 0..8 {
            assert_eq!(site.failure(FailureStage::HttpPreAuth), first);
        }
        match first {
            StageResponse::Http(response) => {
                assert_eq!(response.status, 404);
                assert!(!String::from_utf8_lossy(&response.body).contains("auth"));
                assert_eq!(response.cache_control, "no-store");
            }
            other => panic!("expected an HTTP failure, got {other:?}"),
        }
    }

    /// §9.1: after a WS upgrade only frames or a Close are legal, never HTML.
    #[test]
    fn ws_stage_failures_use_close_not_html() {
        let site = Site::builtin();
        assert_eq!(
            site.failure(FailureStage::WsPreAuth),
            StageResponse::WsClose(1000)
        );
    }

    /// §9.1: after SSE has started, only bounded events are legal.
    #[test]
    fn sse_stage_failures_use_events_not_status_codes() {
        let site = Site::builtin();
        match site.failure(FailureStage::SseStarted) {
            StageResponse::SseComment(bytes) => {
                let text = String::from_utf8(bytes).unwrap();
                assert!(text.starts_with(':'), "must be an SSE comment: {text}");
                assert!(text.ends_with("\n\n"), "must terminate the event: {text}");
            }
            other => panic!("expected an SSE event, got {other:?}"),
        }
    }

    #[test]
    fn json_appearance_is_selectable() {
        let site = Site::builtin().with_appearance(FailureAppearance::Json);
        match site.failure(FailureStage::HttpPreAuth) {
            StageResponse::Http(response) => {
                assert_eq!(response.content_type, "application/json");
                assert!(String::from_utf8_lossy(&response.body).contains("not_found"));
            }
            other => panic!("expected an HTTP failure, got {other:?}"),
        }
    }

    /// §9.2: the failure appearance is bounded.
    #[test]
    fn failure_body_is_bounded() {
        let site = Site::builtin()
            .with_not_found(vec![b'x'; FAILURE_MAX_BODY + 5_000])
            .unwrap();
        match site.failure(FailureStage::HttpPreAuth) {
            StageResponse::Http(response) => {
                assert_eq!(response.body.len(), FAILURE_MAX_BODY);
            }
            other => panic!("expected an HTTP failure, got {other:?}"),
        }
    }

    /// §6.5: content is injectable, so instances need not share one template.
    #[test]
    fn home_content_can_be_injected() {
        let site = Site::builtin()
            .with_home(b"<html>custom</html>".to_vec())
            .unwrap();
        let response = site.route("/").unwrap();
        assert_eq!(response.body, b"<html>custom</html>");
    }

    #[test]
    fn oversized_injected_resources_are_rejected() {
        assert!(matches!(
            Site::builtin().with_home(vec![b'x'; MAX_SITE_RESOURCE + 1]),
            Err(SiteError::ResourceTooLarge { .. })
        ));
        assert!(matches!(
            Site::builtin().with_not_found(vec![b'x'; MAX_SITE_RESOURCE + 1]),
            Err(SiteError::ResourceTooLarge { .. })
        ));
    }

    /// Ordinary site assets may be cached; the failure page must not be.
    #[test]
    fn caching_policy_differs_between_assets_and_failures() {
        let site = Site::builtin();
        assert!(site
            .route("/robots.txt")
            .unwrap()
            .cache_control
            .contains("max-age"));
        match site.failure(FailureStage::HttpPreAuth) {
            StageResponse::Http(response) => assert_eq!(response.cache_control, "no-store"),
            other => panic!("expected an HTTP failure, got {other:?}"),
        }
    }

    #[test]
    fn favicon_is_a_gif() {
        let site = Site::builtin();
        let response = site.route("/favicon.ico").unwrap();
        assert!(response.body.starts_with(b"GIF89a"));
    }

    #[test]
    fn robots_disallows_the_carrier_paths() {
        let site = Site::builtin();
        let text = String::from_utf8(site.route("/robots.txt").unwrap().body).unwrap();
        for path in RESERVED_PATHS {
            assert!(text.contains(path), "robots.txt should disallow {path}");
        }
    }
}
