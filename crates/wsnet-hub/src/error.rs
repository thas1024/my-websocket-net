//! Startup errors (DESIGN.md section 9.3).
//!
//! Section 9.3 is a *startup* requirement as much as a runtime one: "监听非
//! loopback 必須 username/password 加来源 allowlist，否则启动拒绝". For the Hub
//! backend the rule is stricter still, because section 11's deployment puts nginx
//! in front of it: the backend is loopback-only, and a configuration that would
//! expose it directly is refused before a socket is bound.

use wsnet_auth_store::AuthStoreError;
use wsnet_config::ConfigError;
use wsnet_routing::AclError;

/// Why the Hub refused to start.
#[derive(Debug, thiserror::Error)]
pub enum HubStartError {
    /// The configured listener is reachable from off-host.
    #[error("`{0}` is not a loopback listen address; the Hub backend must stay behind a TLS reverse proxy (section 9.3)")]
    NonLoopbackListen(String),
    /// The listen address was not `host:port`, or named a host this build cannot
    /// resolve without DNS.
    #[error("`{0}` is not a usable `host:port` listener address")]
    InvalidListen(String),
    /// The configuration itself is invalid.
    #[error("configuration: {0}")]
    Config(#[from] ConfigError),
    /// The ACL could not be compiled.
    #[error("acl: {0}")]
    Acl(#[from] AclError),
    /// The nonce store could not be created.
    #[error("authentication nonce store: {0}")]
    NonceStore(#[from] AuthStoreError),
    /// A node's credential file could not be read.
    #[error("cannot read `{path}`: {message}")]
    SecretFile {
        /// Path that failed.
        path: String,
        /// Operating-system message.
        message: String,
    },
    /// A node's credential file did not hold a 32-byte key.
    #[error("`{path}` does not hold a 32-byte key, in raw or hex form")]
    BadSecret {
        /// Path that failed.
        path: String,
    },
}
