//! The authorization-code-with-PKCE flow against Google.
//!
//! This module discovers the issuer, builds the redirect that starts sign-in,
//! and exchanges the returned code for a verified identity. The verification
//! itself lives in [`crate::oidc`]; this module is the OAuth choreography
//! around it.
//!
//! # The HTTP client
//!
//! Discovery and the token exchange need an async HTTP client. We do **not**
//! use openidconnect's bundled reqwest client: its default features drag
//! native-tls and OpenSSL into a rustls-only workspace (see the crate's
//! `Cargo.toml` and `deny.toml`). Instead the flow runs over the platform's own
//! `reqwest` 0.13 through a small executor closure — openidconnect accepts any
//! `Fn(HttpRequest) -> Future` as its client.
//!
//! The caller builds that `reqwest::Client` and must disable redirects on it:
//! the token endpoint is a credentialed POST, and following a redirect from it
//! is how a client secret ends up at a host nobody chose.

use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreJsonWebKeySet, CoreProviderMetadata,
};
use openidconnect::url::Url;
use openidconnect::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, HttpRequest, HttpResponse,
    IssuerUrl, Nonce, OAuth2TokenResponse as _, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    RequestTokenError, Scope, TokenResponse as _, TokenUrl,
};

use std::future::Future;
use std::pin::Pin;

use openidconnect::AsyncHttpClient;

use crate::oidc::{GoogleIdToken, VerifiedIdentity, verify_id_token};

/// Scopes requested at sign-in beyond `openid`, which the OIDC flow adds
/// itself. `email` is the one profile claim `#10` needs to key a user.
const EXTRA_SCOPES: [&str; 1] = ["email"];

/// Static configuration for the Google OIDC client.
///
/// `client_secret` is held as an [`openidconnect::ClientSecret`], whose `Debug`
/// prints `ClientSecret([redacted])` — the flow never logs the raw value.
#[non_exhaustive]
pub struct OidcConfig {
    /// The OAuth client id issued by Google.
    pub client_id: String,
    /// The OAuth client secret issued by Google.
    pub client_secret: String,
    /// Our callback URL, e.g. `https://clwd.run/auth/google/callback`.
    pub redirect_uri: String,
    /// The issuer, normally `https://accounts.google.com`.
    pub issuer: String,
}

impl OidcConfig {
    /// Assemble the configuration. A constructor because the type is
    /// `#[non_exhaustive]`, which otherwise leaves callers outside this crate
    /// unable to build one.
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        issuer: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            issuer: issuer.into(),
        }
    }
}

/// A configured Google OIDC flow: the client identity plus the endpoints and
/// keys discovered from the issuer.
///
/// ponytail: the JWKS is fetched once, at discovery. Google rotates keys on a
/// days-to-weeks schedule and publishes the next one ahead of use, so a process
/// restarted within that window is fine; a long-lived one needs a refetch on an
/// unknown `kid`, which is a `discover` call behind a lock.
pub struct Flow {
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_uri: RedirectUrl,
    issuer: IssuerUrl,
    auth_uri: AuthUrl,
    token_uri: TokenUrl,
    jwks: CoreJsonWebKeySet,
}

/// Why discovery or a code exchange failed.
///
/// Two variants because the caller owes the user two different answers:
/// [`FlowError::Rejected`] is "this sign-in is not valid, start over";
/// [`FlowError::Unavailable`] is "the identity provider could not be reached",
/// which is not the user's fault and must not be reported as if it were. The
/// strings are for the log, never the caller.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FlowError {
    /// The provider answered, and the answer was no — or was not a valid
    /// answer: a burned or unknown code, a PKCE mismatch, a malformed
    /// response, or an ID token that failed verification.
    #[error("the sign-in was rejected: {0}")]
    Rejected(String),
    /// The provider could not be reached.
    #[error("the identity provider is unavailable: {0}")]
    Unavailable(String),
}

/// What starting sign-in produces: the URL to send the browser to, and the
/// three secrets the callback must recover to finish safely.
///
/// The `state`, `nonce` and `pkce_verifier` are stored browser-bound in a
/// signed cookie between the redirect and the callback. None of them may be
/// guessable by, or readable to, another browser.
///
/// All four are exposed as `&str`, deliberately: the caller (`control-plane`)
/// stores them in a cookie and passes them back to [`Flow`] verbatim, and must
/// not need to depend on `openidconnect`'s types to do it. Keeping the OIDC
/// library out of the router is what lets the flow cookie's serialization stay
/// trivial and a provider swap stay contained here.
pub struct Authorization {
    url: Url,
    state: CsrfToken,
    nonce: Nonce,
    pkce_verifier: PkceCodeVerifier,
}

impl Authorization {
    /// Where to redirect the browser to begin sign-in.
    #[must_use]
    pub fn redirect_to(&self) -> &str {
        self.url.as_str()
    }

    /// The CSRF token echoed back as `state`; the callback rejects a mismatch.
    #[must_use]
    pub fn state(&self) -> &str {
        self.state.secret()
    }

    /// The nonce bound into the ID token; the callback rejects a mismatch.
    #[must_use]
    pub fn nonce(&self) -> &str {
        self.nonce.secret()
    }

    /// The PKCE verifier the callback presents at the token exchange.
    #[must_use]
    pub fn pkce_verifier(&self) -> &str {
        self.pkce_verifier.secret()
    }
}

impl Flow {
    /// Discover the issuer's endpoints and signing keys.
    ///
    /// # Errors
    ///
    /// [`FlowError::Unavailable`] if the discovery document or the JWKS cannot
    /// be fetched; [`FlowError::Rejected`] if the configuration is malformed or
    /// the issuer's document is invalid (including an `issuer` that does not
    /// match the one configured, which `openidconnect` checks).
    pub async fn discover(config: OidcConfig, http: &reqwest::Client) -> Result<Self, FlowError> {
        let bad = |what: &str, e: openidconnect::url::ParseError| {
            FlowError::Rejected(format!("{what}: {e}"))
        };
        let issuer = IssuerUrl::new(config.issuer).map_err(|e| bad("issuer", e))?;
        let redirect_uri =
            RedirectUrl::new(config.redirect_uri).map_err(|e| bad("redirect uri", e))?;

        let exec = Http(http);
        let metadata = CoreProviderMetadata::discover_async(issuer.clone(), &exec)
            .await
            .map_err(|e| match e {
                openidconnect::DiscoveryError::Request(e) => FlowError::Unavailable(e.to_string()),
                other => FlowError::Rejected(other.to_string()),
            })?;

        let token_uri = metadata
            .token_endpoint()
            .cloned()
            .ok_or_else(|| FlowError::Rejected("the issuer advertises no token endpoint".into()))?;

        Ok(Self {
            client_id: ClientId::new(config.client_id),
            client_secret: ClientSecret::new(config.client_secret),
            redirect_uri,
            issuer,
            auth_uri: metadata.authorization_endpoint().clone(),
            token_uri,
            jwks: metadata.jwks().clone(),
        })
    }

    /// Exchange the callback's `code` for a verified identity.
    ///
    /// `pkce_verifier` and `nonce` are the values [`Flow::authorize`] handed
    /// out for this sign-in, recovered by the caller from its flow cookie.
    ///
    /// # Single use lives here
    ///
    /// The provider burns an authorization code on its first exchange, and
    /// PKCE binds the exchange to this flow's verifier. A replayed callback
    /// therefore fails *here*, as [`FlowError::Rejected`] — this call is the
    /// replay boundary, not the caller's flow cookie.
    ///
    /// # Errors
    ///
    /// [`FlowError::Rejected`] for a refused exchange, a response without an
    /// ID token, or an ID token that fails any check in
    /// [`crate::oidc::verify_id_token`]; [`FlowError::Unavailable`] if the
    /// token endpoint cannot be reached.
    pub async fn exchange(
        &self,
        http: &reqwest::Client,
        code: &str,
        pkce_verifier: &str,
        nonce: &str,
    ) -> Result<VerifiedIdentity, FlowError> {
        let client = CoreClient::new(
            self.client_id.clone(),
            self.issuer.clone(),
            self.jwks.clone(),
        )
        .set_client_secret(self.client_secret.clone())
        .set_token_uri(self.token_uri.clone())
        .set_redirect_uri(self.redirect_uri.clone());

        let exec = Http(http);
        let response = client
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_owned()))
            .request_async(&exec)
            .await
            .map_err(|e| match e {
                RequestTokenError::Request(e) => FlowError::Unavailable(e.to_string()),
                other => FlowError::Rejected(other.to_string()),
            })?;
        // Read to keep the response honest about being a bearer response; the
        // access token itself is never used — sign-in needs only the ID token.
        let _ = response.token_type();

        // `CoreTokenResponse` parses the ID token as `CoreIdToken`, whose
        // additional-claims slot is empty and would drop `hd`. Re-parse the raw
        // JWT as `GoogleIdToken` so the hosted domain survives; the signature
        // and every other check run on this re-parsed token.
        let raw = response
            .id_token()
            .ok_or_else(|| FlowError::Rejected("the token response carries no ID token".into()))?
            .to_string();
        let token = raw
            .parse::<GoogleIdToken>()
            .map_err(|e| FlowError::Rejected(e.to_string()))?;

        verify_id_token(
            &token,
            &client.id_token_verifier(),
            &Nonce::new(nonce.to_owned()),
        )
        .map_err(|e| FlowError::Rejected(e.to_string()))
    }

    /// Build the redirect that starts sign-in.
    ///
    /// The returned URL carries `response_type=code`, the client id, the
    /// redirect URI, the `openid` and `email` scopes, a random `state`, a random
    /// `nonce`, and a PKCE **S256** challenge. The matching `state`, `nonce` and
    /// PKCE verifier come back in [`Authorization`] for the caller to persist.
    #[must_use]
    pub fn authorize(&self) -> Authorization {
        let client = CoreClient::new(
            self.client_id.clone(),
            self.issuer.clone(),
            self.jwks.clone(),
        )
        .set_auth_uri(self.auth_uri.clone())
        .set_redirect_uri(self.redirect_uri.clone());

        // S256, never plain: a plain challenge is the verifier in the clear.
        let (challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut request = client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in EXTRA_SCOPES {
            request = request.add_scope(Scope::new(scope.to_owned()));
        }
        let (url, state, nonce) = request.set_pkce_challenge(challenge).url();

        Authorization {
            url,
            state,
            nonce,
            pkce_verifier,
        }
    }

    /// Construct from already-known parts, so `authorize` can be exercised
    /// without a network round trip.
    #[cfg(test)]
    fn from_parts(
        client_id: ClientId,
        redirect_uri: RedirectUrl,
        issuer: IssuerUrl,
        auth_uri: AuthUrl,
        jwks: CoreJsonWebKeySet,
    ) -> Self {
        Self {
            client_id,
            client_secret: ClientSecret::new("unused".to_owned()),
            redirect_uri,
            issuer,
            auth_uri,
            token_uri: TokenUrl::new("https://unused.invalid/token".to_owned()).expect("url"),
            jwks,
        }
    }
}

/// `openidconnect`'s client over the platform's `reqwest`.
///
/// A named type rather than the `Fn(HttpRequest) -> Future` closure the crate
/// also accepts: a closure's future is generic over a higher-ranked lifetime,
/// and the compiler cannot prove it `Send` for every one — which an axum
/// handler awaiting it requires. Boxing as `Send` here states it once.
struct Http<'a>(&'a reqwest::Client);

impl<'c> AsyncHttpClient<'c> for Http<'_> {
    type Error = reqwest::Error;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, reqwest::Error>> + Send + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(execute(self.0, request))
    }
}

/// Run one `openidconnect` request over the platform's `reqwest`.
async fn execute(
    http: &reqwest::Client,
    request: HttpRequest,
) -> Result<HttpResponse, reqwest::Error> {
    let (parts, body) = request.into_parts();
    let response = http
        .request(parts.method, parts.uri.to_string())
        .headers(parts.headers)
        .body(body)
        .send()
        .await?;

    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await?.to_vec();

    let mut out = HttpResponse::new(body);
    *out.status_mut() = status;
    *out.headers_mut() = headers;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const CLIENT_ID: &str = "test-client-id.apps.googleusercontent.com";
    const REDIRECT: &str = "https://clwd.run/auth/google/callback";
    const AUTH_URI: &str = "https://accounts.google.com/o/oauth2/v2/auth";

    fn flow() -> Flow {
        Flow::from_parts(
            ClientId::new(CLIENT_ID.to_owned()),
            RedirectUrl::new(REDIRECT.to_owned()).expect("redirect url"),
            IssuerUrl::new("https://accounts.google.com".to_owned()).expect("issuer url"),
            AuthUrl::new(AUTH_URI.to_owned()).expect("auth url"),
            CoreJsonWebKeySet::new(vec![]),
        )
    }

    fn query(url: &Url) -> HashMap<String, String> {
        url.query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    #[test]
    fn authorize_redirect_carries_pkce_state_nonce_and_scopes() {
        let auth = flow().authorize();
        let url = Url::parse(auth.redirect_to()).expect("a valid redirect url");
        let q = query(&url);

        assert_eq!(q.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(q.get("client_id").map(String::as_str), Some(CLIENT_ID));
        assert_eq!(q.get("redirect_uri").map(String::as_str), Some(REDIRECT));

        let scope = q.get("scope").expect("a scope parameter");
        assert!(scope.split(' ').any(|s| s == "openid"), "openid: {scope}");
        assert!(scope.split(' ').any(|s| s == "email"), "email: {scope}");

        // PKCE must be S256, never plain — a `plain` challenge is the verifier
        // in the clear and defeats the point of PKCE.
        assert_eq!(
            q.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert!(q.contains_key("code_challenge"), "a PKCE challenge");

        // The URL's state/nonce are exactly the ones handed back (as strings)
        // for the callback to check against.
        assert_eq!(q.get("state").map(String::as_str), Some(auth.state()));
        assert_eq!(q.get("nonce").map(String::as_str), Some(auth.nonce()));

        // The verifier is a real, non-empty PKCE secret.
        assert!(!auth.pkce_verifier().is_empty(), "a PKCE verifier");
    }
}
