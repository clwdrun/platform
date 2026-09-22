//! The authorization-code-with-PKCE flow against Google.
//!
//! This module builds the redirect that starts sign-in and (in a later slice,
//! with the mock-issuer harness) exchanges the returned code for a verified
//! identity. The verification itself lives in [`crate::oidc`]; this module is
//! the OAuth choreography around it.
//!
//! # The HTTP client
//!
//! Discovery and the token exchange need an async HTTP client. We do **not**
//! use openidconnect's bundled reqwest client: its default features drag
//! native-tls and OpenSSL into a rustls-only workspace (see the crate's
//! `Cargo.toml` and `deny.toml`). Instead the flow runs over the platform's own
//! `reqwest` 0.13 through a small executor closure — openidconnect accepts any
//! `Fn(HttpRequest) -> Future` as its client.

use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreJsonWebKeySet};
use openidconnect::url::Url;
use openidconnect::{
    AuthUrl, ClientId, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope,
};

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

/// A configured Google OIDC flow: the client identity plus the endpoints and
/// keys discovered from the issuer.
pub struct Flow {
    client_id: ClientId,
    redirect_uri: RedirectUrl,
    issuer: IssuerUrl,
    auth_uri: AuthUrl,
    jwks: CoreJsonWebKeySet,
    // `client_secret` and `token_uri` join here with `exchange` (the callback
    // half), which is written against the mock-issuer harness.
}

/// What starting sign-in produces: the URL to send the browser to, and the
/// three secrets the callback must recover to finish safely.
///
/// The `state`, `nonce` and `pkce_verifier` are stored browser-bound in a
/// single-use signed cookie between the redirect and the callback (a later
/// slice). None of them may be guessable by, or readable to, another browser.
#[non_exhaustive]
pub struct Authorization {
    /// Where to redirect the browser to begin sign-in.
    pub url: Url,
    /// The CSRF token echoed back as `state`; the callback rejects a mismatch.
    pub state: CsrfToken,
    /// The nonce bound into the ID token; the callback rejects a mismatch.
    pub nonce: Nonce,
    /// The PKCE verifier the callback presents at the token exchange.
    pub pkce_verifier: PkceCodeVerifier,
}

impl Flow {
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

    /// Construct from already-known parts. Used by discovery (a later slice)
    /// and by tests, so `authorize` can be exercised without a network round
    /// trip.
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
            redirect_uri,
            issuer,
            auth_uri,
            jwks,
        }
    }
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
        let q = query(&auth.url);

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

        // The URL's state/nonce are exactly the ones handed back for the
        // callback to check against.
        assert_eq!(
            q.get("state").map(String::as_str),
            Some(auth.state.secret().as_str())
        );
        assert_eq!(
            q.get("nonce").map(String::as_str),
            Some(auth.nonce.secret().as_str())
        );

        // The verifier is a real, non-empty PKCE secret.
        assert!(!auth.pkce_verifier.secret().is_empty(), "a PKCE verifier");
    }
}
