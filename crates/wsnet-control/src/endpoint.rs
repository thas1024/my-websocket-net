//! Where the local control endpoint lives, and who may reach it.
//!
//! USAGE.md section 2 makes the endpoint per-user and local: a Unix domain socket,
//! or a named pipe on Windows, with the file readable and writable only by the
//! current OS user. The type here enforces the *form* of the endpoint (a pipe name
//! or a socket path, never a network address) and the helpers in [`super::local`]
//! enforce the rest at bind time.

use std::env;
use std::fmt;

/// Why an endpoint value cannot be used.
///
/// These are configuration errors reported before any socket exists, so the CLI
/// can say what was wrong with a user-supplied `--endpoint` value instead of
/// failing later with a platform error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EndpointError {
    /// The endpoint value was empty.
    #[error("control endpoint must not be empty")]
    Empty,
    /// The value contained a character the platform refuses in an endpoint name.
    #[error("control endpoint `{value}` contains `{character}`, which is not allowed")]
    ForbiddenCharacter {
        /// The offending value.
        value: String,
        /// The offending character.
        character: char,
    },
    /// On Windows the endpoint is a pipe name, not a path.
    #[error("`{0}` is a filesystem path, not a named-pipe name")]
    NotAPipeName(String),
    /// On Unix the endpoint must name a socket file.
    #[error("`{0}` does not name a socket file")]
    NotAPath(String),
    /// Something already exists at the path and it is not a socket.
    #[error("`{0}` already exists and is not a socket")]
    NotASocket(String),
    /// The existing socket belongs to another user.
    #[error("`{path}` is owned by uid {owner}, not by this process")]
    NotOwned {
        /// The existing socket.
        path: String,
        /// Its owner.
        owner: u32,
    },
    /// Another daemon is already serving this endpoint.
    #[error("another daemon is already serving `{0}`")]
    InUse(String),
    /// The environment does not identify the current user.
    #[error("cannot determine the current OS user from the environment")]
    UnknownUser,
}

/// A local-only control endpoint.
///
/// The inner value is private and there is deliberately no constructor taking an
/// address: DESIGN.md section 7.6 forbids exposing the management interface on a
/// public API, and the surest way to keep that promise is to make a network
/// address inexpressible. On Windows the value is a pipe *name* (without the
/// `\\.\pipe\` prefix); on Unix it is the socket file path. Unix paths are
/// UTF-8 by construction here, which is what a CLI argument or an environment
/// variable supplies anyway.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint(String);

impl Endpoint {
    /// Builds an endpoint from a pipe name (Windows) or a socket path (Unix).
    ///
    /// A Windows value may include the `\\.\pipe\` prefix, which is stripped; the
    /// rest must be a plain name with no separator in it.
    pub fn new(value: impl Into<String>) -> Result<Self, EndpointError> {
        let value = value.into();
        validate(value).map(Endpoint)
    }

    /// The endpoint as this crate stores it: the pipe name, or the socket path.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The string to hand to the operating system.
    ///
    /// This is `\\.\pipe\<name>` on Windows and the socket path on Unix. It exists
    /// so that other tooling can reach the same endpoint without re-deriving the
    /// platform spelling; it is still a local endpoint, not an address.
    pub fn os_name(&self) -> String {
        os_name(&self.0)
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The default per-user endpoint.
///
/// USAGE.md section 2 requires the daemon and the CLI to meet on the same
/// per-user endpoint without configuration, so the name embeds the current user's
/// identity (see [`user_slug`]). It is derived from the environment on every call
/// and is therefore stable for the lifetime of a process.
///
/// On Windows the pipe name is not the access-control boundary: the pipe is
/// created with the process's default DACL, so only the creating user and the
/// system can open it. On Unix the socket file is the boundary, hence the 0600
/// mode applied at bind time.
pub fn default_endpoint() -> Result<Endpoint, EndpointError> {
    let user = current_user().ok_or(EndpointError::UnknownUser)?;
    if user_slug(&user).is_empty() {
        return Err(EndpointError::UnknownUser);
    }
    Endpoint::new(default_name(&user))
}

/// Reduces an OS user name to the safe character set an endpoint name allows.
///
/// Endpoint names are pipe names and file names, so anything outside
/// `[A-Za-z0-9._-]` (a Windows `DOMAIN\user`, for instance) is folded to `_`
/// rather than escaped, and the result is length-capped because it becomes part
/// of a pipe name. Two different users can in principle fold to the same slug;
/// that costs nothing, because the endpoint's ownership check and the pipe's DACL
/// are what actually separate users.
pub fn user_slug(user: &str) -> String {
    let mut slug = String::with_capacity(user.len());
    for character in user.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            slug.push(character);
        } else {
            slug.push('_');
        }
    }
    slug.truncate(MAX_SLUG_BYTES);
    slug
}

/// Longest user-derived endpoint fragment, in bytes.
///
/// A Windows pipe name is limited to 256 characters in total and the prefix
/// already spends a dozen of them; 64 bytes leaves ample room and keeps the name
/// readable.
const MAX_SLUG_BYTES: usize = 64;

/// The fixed part of the default endpoint name.
fn default_prefix() -> &'static str {
    "wsnet-control-"
}

/// The current OS user's name, from the environment.
///
/// There is no standard-library call for the effective user id, and the workspace
/// has no platform-sys crate, so the name is read from the environment. A missing
/// name is an error rather than a shared fallback: two users silently landing on
/// one endpoint would break the per-user guarantee of USAGE.md section 2.
fn current_user() -> Option<String> {
    ["USERNAME", "USER", "LOGNAME"]
        .iter()
        .filter_map(|key| env::var(key).ok())
        .find(|value| !value.trim().is_empty())
}

/// The default endpoint name for a user, before platform decoration.
fn default_name(user: &str) -> String {
    format!("{}{}", default_prefix(), user_slug(user))
}

/// Validates the stored value for this platform.
#[cfg(windows)]
fn validate(value: String) -> Result<String, EndpointError> {
    const PIPE_PREFIX: &str = r"\\.\pipe\";
    let name = match value.strip_prefix(PIPE_PREFIX) {
        Some(rest) => {
            if rest.is_empty() {
                return Err(EndpointError::Empty);
            }
            rest.to_string()
        }
        None => value,
    };
    if name.is_empty() {
        return Err(EndpointError::Empty);
    }
    for character in name.chars() {
        if character == '\\' || character == '/' {
            // A path here means the caller expected a Unix-style endpoint; on
            // Windows only the part after the pipe prefix may be a name.
            return Err(EndpointError::NotAPipeName(name));
        }
        if character == '\0' {
            return Err(EndpointError::ForbiddenCharacter {
                value: name,
                character,
            });
        }
    }
    Ok(name)
}

/// Validates the stored value for this platform.
#[cfg(unix)]
fn validate(value: String) -> Result<String, EndpointError> {
    if value.is_empty() {
        return Err(EndpointError::Empty);
    }
    if value.contains('\0') {
        return Err(EndpointError::ForbiddenCharacter {
            value,
            character: '\0',
        });
    }
    if value == "."
        || value == ".."
        || value.ends_with('/')
        || value.ends_with("/.")
        || value.ends_with("/..")
    {
        return Err(EndpointError::NotAPath(value));
    }
    Ok(value)
}

/// The platform spelling handed to the operating system.
#[cfg(windows)]
fn os_name(name: &str) -> String {
    format!(r"\\.\pipe\{name}")
}

/// The platform spelling handed to the operating system.
#[cfg(unix)]
fn os_name(name: &str) -> String {
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_slug_keeps_only_endpoint_safe_characters() {
        assert_eq!(user_slug("Administrator"), "Administrator");
        assert_eq!(user_slug(r"DOMAIN\alice"), "DOMAIN_alice");
        assert_eq!(user_slug("a b/c:d"), "a_b_c_d");
        assert_eq!(user_slug(""), "");
    }

    /// Two users must never share a default endpoint name.
    #[test]
    fn different_users_get_different_names() {
        assert_ne!(user_slug("alice"), user_slug("bob"));
        assert_ne!(default_name("alice"), default_name("bob"));
        assert!(default_name("alice").contains(&user_slug("alice")));
    }

    #[test]
    fn the_slug_is_length_capped() {
        assert_eq!(user_slug(&"u".repeat(500)).len(), MAX_SLUG_BYTES);
    }

    #[test]
    fn the_default_endpoint_is_stable_and_names_the_user() {
        let first = default_endpoint().expect("the environment must identify a user");
        let second = default_endpoint().expect("the environment must identify a user");
        assert_eq!(first, second);
        let user = current_user().expect("the environment must identify a user");
        assert!(first.as_str().contains(&user_slug(&user)));
        assert!(!first.as_str().is_empty());
    }

    #[test]
    fn empty_and_hostile_endpoint_values_are_refused() {
        assert_eq!(Endpoint::new("").unwrap_err(), EndpointError::Empty);
        assert!(Endpoint::new("has\0nul").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_endpoints_are_pipe_names() {
        let endpoint = Endpoint::new(r"\\.\pipe\wsnet-control-alice").unwrap();
        assert_eq!(endpoint.as_str(), "wsnet-control-alice");
        assert_eq!(endpoint.os_name(), r"\\.\pipe\wsnet-control-alice");
        // A path is not a pipe name.
        assert!(matches!(
            Endpoint::new(r"\tmp\wsnet.sock").unwrap_err(),
            EndpointError::NotAPipeName(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_endpoints_are_socket_paths() {
        let endpoint = Endpoint::new("/tmp/wsnet-control-alice.sock").unwrap();
        assert_eq!(endpoint.os_name(), "/tmp/wsnet-control-alice.sock");
        assert!(Endpoint::new("/tmp/").is_err());
        assert!(Endpoint::new("/tmp/..").is_err());
    }
}
