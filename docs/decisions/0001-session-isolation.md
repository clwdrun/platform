# Session isolation from untrusted apps (#62)

Decided October 2026. Apps are untrusted, agent-written code that serves HTML and
JavaScript to people's browsers. This records where they are served from, which
cookies exist, and why.

## The decision

**Apps are served from a registrable domain of their own**, `<apps domain>`, never
under the control plane's `clwd.run`. The control plane's session is a host-only
`__Host-` cookie. Each app host gets its own `__Host-` session through a redirect
handshake. The apps domain goes on the Public Suffix List as `*.<apps domain>`, so
every app is its own site.

| | Rejected: (A) harden the old model | Rejected: (C) same domain, `__Host-` + handshake | **Chosen: (B) separate apps domain + handshake** |
|---|---|---|---|
| Cookie tossing onto the control plane | open: script on an app sets `Domain=clwd.run`; no server sees it happen | closed for platform cookies | closed: apps cannot set any cookie on `clwd.run` |
| An app's own `Domain=clwd.run` cookies | reach the control plane and every app (cookie bomb) | same | impossible |
| `SameSite` against apps | useless: apps are same-site | useless | works: apps are cross-site |
| Renderer process | shared with the control plane | shared (Chrome isolates per site) | separate |
| Reputation | one phishing app flags `clwd.run` | same | separate domain |
| Certificate quota | one pool for every org | one pool | per site once the PSL entry ships |
| DNS token | an issuance token is total DNS control of `clwd.run` | same | the apps zone has its own token |

(A) left client-side cookie tossing open, and nothing server-side can close it. (C)
closed it for platform cookies but left apps same-site with the control plane:
shared processes, shared reputation, the cookie bomb, and every future
cookie-prefix bypass in a browser landing on the control plane.

Changing this costs one PR now and a migration plus every shared link later, so
it is decided before anything (#11) builds on a session model.

## Cookies

| Cookie | Host | Set by | Why each attribute |
|---|---|---|---|
| `__Host-clwd_session` | control plane | sign-in | `session::set_cookie` |
| `__Host-clwd_signin` | control plane | sign-in start | `signin::flow_cookie` |
| `__Host-clwd_app_session` | one app host | gateway, after the exchange | `gateway::signin::app_session_cookie` |
| `__Host-clwd_state` | one app host | gateway, at handshake start | `gateway::signin::state_cookie` |
| `__Host-clwd_hs` | one app host | gateway, loop guard | `gateway::signin::counter_cookie` |

Every one is `__Host-`: `Secure`, `Path=/`, no `Domain`, host-only. Every one's
attributes are written in exactly one function, whose doc says why each is there.
App-host cookies are `SameSite=Lax`, not `Strict`: a link to an app from another
site is a cross-site navigation, and under `Strict` the session is withheld on it
and on the redirects after it, so the handshake loops.

Platform cookies are read by one parser, `shared::cookie::find`, which matches the
exact name byte for byte and refuses duplicates. The `cookie` crate's parsers repair
names (they trim Unicode whitespace into the real name) and are banned in
`clippy.toml`.

## The handshake

1. A visitor reaches `notes.acme.<apps domain>` with no app-host session. The
   gateway asks the control plane (internal listener) to begin a handshake for the
   app with the same-host path asked for, sets the returned state as
   `__Host-clwd_state`, and redirects to `/authorize?state=…`.
2. The control plane finds the handshake by its state. With no control-plane
   session, it signs the visitor in first (`/auth/google?resume=<state>`) and comes
   back. It issues a single-use, 60-second code bound to the handshake and the
   session, and redirects to `https://<the handshake's app host>/__clwd/callback`.
   The host comes from the app row. There is no host or redirect parameter.
3. The gateway checks the callback's `state` against the state cookie, exchanges
   code and state server-to-server (internal listener, internal credential), sets
   `__Host-clwd_app_session`, and redirects to the stored path.

On a state mismatch the gateway restarts the handshake instead of dead-ending, so
two concurrent tabs both end signed in. More than four handshakes from one browser
for one host in a minute shows an error rather than another redirect. Redirects
carrying a code or state send `Referrer-Policy: no-referrer` and `Cache-Control:
no-store`, and no log line carries a query string.

First visit: three redirects and one server-to-server call; Google adds its own
round trip when the visitor is not signed in to the control plane.

## The per-request check

One statement, an index probe on `app_sessions.secret_sha256`:

```sql
select exists (
  select 1 from app_sessions a
    join sessions s on s.id = a.parent_session_id
    join users u on u.id = s.user_id
   where a.secret_sha256 = $1 and a.app_id = $2
     and a.expires_at > now()
     and s.revoked_at is null and s.expires_at > now()
     and u.deleted_at is null)
```

Looked up by the session *and the app being requested*, so a session for one app is
no session on another. The parent is checked in the same statement, so signing out
ends every app-host session on its next request. Nothing is cached: revocation
latency is zero, and #12's cache must keep that or argue for a bound.

## What the gateway strips

- Platform cookies (`__Host-clwd_*`, `__Secure-clwd_*`, matched case-insensitively)
  are removed from `Cookie` before a request reaches the app; the app's own pass
  through byte for byte.
- A request carrying a platform cookie twice gets `gateway.duplicate_cookie`.
- An app's `Set-Cookie` for a platform name, including the nameless
  `=__Host-clwd_x=v` form, is dropped before the browser sees it.
- `/__clwd/` is the platform's: never forwarded, and an app's own route there gets
  `gateway.reserved_path`.

Only a request with a valid app-host session for the requested app reaches the app
hop, and the hop's target is the app row the control plane resolved for the host,
never anything in the request. There is no production hop yet (#11 adds the
runtime); until then a live app answers `gateway.not_ready` as before.

## What an app's page can still do

- **On its own host**, plant or evict-and-replace its own state or session cookie,
  so a visitor uses that one app as someone else. The app already serves every byte
  on that host, so this gains it nothing it could not do directly. It never reaches
  the control plane or another app.
- **Until the PSL entry ships in browsers**, app hosts are same-site with each other.
  App A can set `__Secure-` or unprefixed cookies with `Domain=<apps domain>` that
  reach app B. The gateway never reads them as a session and strips the
  `__Secure-clwd_*` ones, but app B's own unprefixed cookies are tossable. On a
  browser without the nameless-cookie fix, app A can set a cookie that serialises as
  `__Host-clwd_app_session=<v>` for app B; with `<v>` a session the attacker got for
  B themselves, a victim with no B session uses B as the attacker. The `(secret,
  app)` lookup stops a session for A being used on B, and duplicate refusal protects
  a victim who already holds one. The window is: unpatched browsers, before the PSL
  entry. The cookie bomb across the apps domain has the same window.

## Verification sources

- RFC 6265bis (draft, httpwg, 2026-10-07): §4.1.3.2 `__Host-`; §5.4 prefixes match
  case-insensitively; §5.7 step 22 rejects nameless cookies with prefixed values;
  step 23.2 script cannot overwrite an `HttpOnly` cookie.
- Firefox: CVE-2022-40958 (nameless, fixed in 105); CVE-2024-5699 (case-insensitive
  prefixes). Chromium: nameless `__Host-` rejection cited as crbug 40060319 on the
  IETF list; version unconfirmed. Safari: unconfirmed.
- Public Suffix List guidelines: `_psl` TXT record kept permanently; more than two
  years of registration; no SLA on review; suffixes whose sole purpose is avoiding a
  CA's rate limits are refused.
- Let's Encrypt rate limits ("we use the Public Suffix List to identify registered
  domains"); Boulder `ratelimits/utilities.go` uses publicsuffix-go with private
  entries included; Boulder `policy/pa.go` refuses a wildcard only on an ICANN TLD;
  CA/B Forum Ballot 202, §3.2.2.6, says to consult only the ICANN section.
- Chromium Site Isolation: a site is scheme plus registered domain;
  `kOriginKeyedProcessesByDefault` is disabled by default (`content_features.cc`).

## The browser tests

`crates/e2e/tests/browser.rs` runs headless Chrome against the real control plane
and gateway, with the test certificate trusted only by its pinned key. A permanent
negative control proves an unpinned browser loads nothing. It caught chromiumoxide's
default of ignoring every certificate error, which would otherwise have made every
test pass for the wrong reason.

## Cutover

Everything above runs on the placeholder `clwd-apps.test`. Production waits for:
the domain registered with auto-renew and registrar lock, the `_psl` TXT record
live, the PSL entry merged, a Let's Encrypt **staging** issuance of
`*.<test org>.<apps domain>` once both exist (Pebble does not model the PSL), HSTS,
then the configuration change.
