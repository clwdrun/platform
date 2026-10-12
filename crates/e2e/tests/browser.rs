//! Session isolation, in a real browser (#62), and identity injection with
//! the real worker running a real component (#11).
//!
//! A test of what the server sends is not a test of what the browser accepts:
//! cookie prefixes, `Domain` scoping and overwrite rules are browser
//! behaviour. Each test here has an app's page — or a raw request a browser
//! would never send — attack, and asserts on what arrives: the cookie jar
//! Chrome would send, the rows the control plane wrote, and what reached the
//! app hop.

mod support;

use support::{
    ATTACKER_APP, CONTROL_PLANE, Chrome, EVIL, Harness, NOTES, WIKI, app_name, cookie_key, logs,
    text, url, wait_to_leave,
};

use std::sync::Arc;

use control_plane::session;
use sqlx::PgPool;

const APP_SESSION: &str = "__Host-clwd_app_session";

/// Sign in by opening `host`: gateway → control plane → (mock) Google →
/// control plane → app callback → the app. Returns the tab, on the app.
async fn open_app(chrome: &Chrome, host: &str, path: &str) -> chromiumoxide::Page {
    let page = chrome.open(&format!("https://{host}{path}")).await;
    let label = host.split('.').next().unwrap_or(host);
    assert!(
        app_name(&page).await == label,
        "expected app {label} at {}: {:?}",
        url(&page).await,
        text(&page).await
    );
    page
}

async fn cookie(
    chrome: &Chrome,
    page: &chromiumoxide::Page,
    host: &str,
    name: &str,
) -> Vec<(String, String)> {
    chrome
        .cookies_for(page, &format!("https://{host}/"))
        .await
        .into_iter()
        .filter(|(n, _, _)| n.eq_ignore_ascii_case(name))
        .map(|(n, v, _)| (n, v))
        .collect()
}

/// A control-plane session made directly, for a second actor (the attacker)
/// who never uses the browser. Returns the `Cookie` pair and its session id.
async fn control_plane_session(
    pool: &PgPool,
    email: &str,
) -> (String, control_plane::ids::SessionId) {
    let user = control_plane::db::create_user(pool, email)
        .await
        .expect("user");
    let issued = session::issue(pool, &cookie_key(), user.id)
        .await
        .expect("issue")
        .expect("a session");
    let pair = issued
        .set_cookie
        .split(';')
        .next()
        .expect("pair")
        .to_owned();
    (pair, issued.id)
}

fn location(response: &reqwest::Response) -> String {
    response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned()
}

fn set_cookie_value(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| {
            c.split(';')
                .next()?
                .strip_prefix(&format!("{name}="))
                .map(str::to_owned)
        })
}

/// The handshake state cookie a response sets, as `(name, value)`. One per
/// handshake in flight, named `__Host-clwd_state.<id>` (#83).
fn state_cookie_set(response: &reqwest::Response) -> Option<(String, String)> {
    state_cookies_set(response)
        .into_iter()
        .find(|(_, value, max_age)| !value.is_empty() && *max_age > 0)
        .map(|(name, value, _)| (name, value))
}

/// Every state cookie a response sets or clears: `(name, value, max_age)`.
fn state_cookies_set(response: &reqwest::Response) -> Vec<(String, String, i64)> {
    response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|c| {
            let (pair, attributes) = c.split_once(';')?;
            let (name, value) = pair.split_once('=')?;
            name.starts_with("__Host-clwd_state.").then(|| {
                let max_age = attributes
                    .split(';')
                    .find_map(|a| a.trim().strip_prefix("Max-Age="))
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(0);
                (name.to_owned(), value.to_owned(), max_age)
            })
        })
        .collect()
}

/// The `state` query parameter of an `/authorize` URL.
fn state_of(authorize: &str) -> String {
    authorize
        .split("state=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("state")
        .to_owned()
}

/// The harness is real: `__Host-` cookies are set and sent, host-only. And
/// without the pinned certificate the same harness loads nothing — the
/// permanent negative control that keeps a TLS mistake from becoming a quiet
/// pass.
#[sqlx::test(migrations = "../../migrations")]
async fn host_only_cookies_are_really_set_and_tls_is_really_checked(pool: PgPool) {
    let h = Harness::start(pool).await;
    let chrome = h.browser().await;
    let page = open_app(&chrome, NOTES, "/").await;

    let cp = chrome
        .cookies_for(&page, &format!("https://{CONTROL_PLANE}/"))
        .await;
    let session = cp
        .iter()
        .find(|(n, _, _)| n == session::COOKIE_NAME)
        .expect("control-plane session in the jar");
    assert_eq!(
        session.2, CONTROL_PLANE,
        "host-only: no leading dot, no parent domain"
    );
    let app = chrome
        .cookies_for(&page, &format!("https://{NOTES}/"))
        .await;
    let app_session = app
        .iter()
        .find(|(n, _, _)| n == APP_SESSION)
        .expect("app-host session in the jar");
    assert_eq!(app_session.2, NOTES);
    assert!(
        cookie(&chrome, &page, WIKI, APP_SESSION).await.is_empty(),
        "one app's session is not another's"
    );

    let blind = h.no_bypass_browser().await;
    let tab = blind.browser.new_page("about:blank").await.expect("tab");
    let _ = tab.goto(format!("https://{NOTES}/")).await;
    assert_eq!(
        app_name(&tab).await,
        "",
        "without the pinned certificate nothing must load"
    );
}

/// Test 1. Cookie tossing at the control plane.
///
/// The negative control first: a page on the control plane's own registrable
/// domain (the model #62 replaced) *can* plant the old `__Secure-` session
/// name on it — so this test can see tossing when it happens. Then: the
/// `__Host-` session cannot be planted even from that sibling, and an app on
/// the apps domain can plant nothing on the control plane at all.
#[sqlx::test(migrations = "../../migrations")]
async fn an_app_cannot_toss_a_session_onto_the_control_plane(pool: PgPool) {
    let h = Harness::start(pool).await;
    let chrome = h.browser().await;
    let page = open_app(&chrome, NOTES, "/").await;
    let real = cookie(&chrome, &page, CONTROL_PLANE, session::COOKIE_NAME).await;
    assert_eq!(real.len(), 1, "signed in to the control plane: {real:?}");

    let plant = |host: &str, c: &str| {
        format!(
            "https://{host}/plant?cookie={}",
            c.replace(' ', "%20")
                .replace(';', "%3B")
                .replace('=', "%3D")
        )
    };
    // Negative control: the old cookie, from a same-site sibling, gets through.
    chrome
        .open(&plant(
            EVIL,
            "__Secure-clwd_session=tossed; Domain=clwd.test; Path=/; Secure",
        ))
        .await;
    assert_eq!(
        cookie(&chrome, &page, CONTROL_PLANE, "__Secure-clwd_session").await,
        vec![("__Secure-clwd_session".to_owned(), "tossed".to_owned())],
        "the harness must be able to see a tossed cookie"
    );

    // The __Host- session, from the same sibling: refused by the browser.
    chrome
        .open(&plant(
            EVIL,
            "__Host-clwd_session=tossed; Domain=clwd.test; Path=/; Secure",
        ))
        .await;
    // And from an app on the apps domain: the control plane's domain is not
    // its own, so neither name lands.
    chrome
        .open(&format!(
            "https://{NOTES}/plant?cookie={}",
            "__Host-clwd_session%3Dfrom-app%3B%20Domain%3Dclwd.test%3B%20Path%3D%2F%3B%20Secure"
        ))
        .await;
    assert_eq!(
        cookie(&chrome, &page, CONTROL_PLANE, session::COOKIE_NAME).await,
        real,
        "the control plane's session is the one it set, and only that one"
    );
}

/// Test 2. An app's `Set-Cookie` for a platform name never reaches the jar.
#[sqlx::test(migrations = "../../migrations")]
async fn an_apps_set_cookie_for_a_platform_name_never_reaches_the_browser(pool: PgPool) {
    let h = Harness::start(pool).await;
    let chrome = h.browser().await;
    let page = open_app(&chrome, NOTES, "/").await;
    let before = cookie(&chrome, &page, NOTES, APP_SESSION).await;
    chrome.open(&format!("https://{NOTES}/set-reserved")).await;

    let jar = chrome
        .cookies_for(&page, &format!("https://{NOTES}/"))
        .await;
    assert!(jar.iter().all(|(_, v, _)| v != "planted-by-app"), "{jar:?}");
    assert_eq!(cookie(&chrome, &page, NOTES, APP_SESSION).await, before);
    assert!(
        jar.iter().any(|(n, v, _)| n == "app_theme" && v == "dark"),
        "the app's own cookie passes: {jar:?}"
    );
}

/// Test 3. App B cannot plant an app-host session or state on app A.
///
/// The `__Host-` names cannot be set with `Domain=`, so neither lands. A
/// `__Secure-` cookie with `Domain=<apps domain>` **does** land on app A —
/// until the PSL entry ships, app hosts are same-site with each other (the
/// residual window #62 names). It is not a name the gateway reads, and the
/// gateway strips every `__Secure-clwd_*` cookie before app A's code runs.
#[sqlx::test(migrations = "../../migrations")]
async fn one_app_cannot_plant_platform_cookies_on_another(pool: PgPool) {
    let h = Harness::start(pool).await;
    let chrome = h.browser().await;
    let page = open_app(&chrome, NOTES, "/").await;
    // App B is another org's. Under the interim member rule the visitor must
    // be able to reach it for the attack to exist at all — as a grant will
    // allow once #15/#16 land.
    h.join("other").await;
    open_app(&chrome, ATTACKER_APP, "/").await;
    let session = cookie(&chrome, &page, NOTES, APP_SESSION).await;
    for c in [
        "__Host-clwd_app_session=from-b; Domain=clwd-apps.test; Path=/; Secure",
        "__Host-clwd_state=from-b; Domain=clwd-apps.test; Path=/; Secure",
        "__Secure-clwd_app_session=from-b; Domain=clwd-apps.test; Path=/; Secure",
    ] {
        chrome
            .open(&format!(
                "https://{ATTACKER_APP}/plant?cookie={}",
                c.replace(' ', "%20")
                    .replace(';', "%3B")
                    .replace('=', "%3D")
                    .replace('/', "%2F")
            ))
            .await;
    }
    let jar = chrome
        .cookies_for(&page, &format!("https://{NOTES}/"))
        .await;
    assert!(
        jar.iter()
            .all(|(n, v, _)| !(n.starts_with("__Host-") && v == "from-b")),
        "no __Host- cookie from app B: {jar:?}"
    );
    assert_eq!(cookie(&chrome, &page, NOTES, APP_SESSION).await, session);
    assert!(
        cookie(&chrome, &page, NOTES, "__Host-clwd_state")
            .await
            .is_empty(),
        "{jar:?}"
    );

    // The __Secure- one landed (pre-PSL); it never reaches app A's code, and
    // app A still works on its own session.
    let echo = chrome
        .open(&format!("https://{NOTES}/echo?probe=after-b"))
        .await;
    assert_eq!(app_name(&echo).await, "", "echo page, not an error");
    let seen = text(&echo).await.to_ascii_lowercase();
    assert!(!seen.contains("clwd_"), "{seen}");
    assert!(h.upstream.saw("notes", "/echo?probe=after-b"));
}

/// Test 4. The nameless and case-variant forms of a platform cookie, carrying
/// a *valid* session, are not accepted by our server parser — whatever the
/// browser's patch level. The exact name, the positive control, is.
#[sqlx::test(migrations = "../../migrations")]
async fn nameless_and_case_variant_session_cookies_are_refused_by_the_gateway(pool: PgPool) {
    let h = Harness::start(pool).await;
    let chrome = h.browser().await;
    let page = open_app(&chrome, NOTES, "/").await;
    let (_, secret) = cookie(&chrome, &page, NOTES, APP_SESSION).await.remove(0);
    let http = h.http();
    for (i, (header, served)) in [
        (format!("={APP_SESSION}={secret}"), false),
        (format!("__HOST-clwd_app_session={secret}"), false),
        (format!("{APP_SESSION}={secret}"), true),
    ]
    .into_iter()
    .enumerate()
    {
        let probe = format!("/echo?probe=nameless-{i}");
        let response = http
            .get(format!("https://{NOTES}{probe}"))
            .header(reqwest::header::COOKIE, &header)
            .send()
            .await
            .expect("request");
        assert_eq!(
            h.upstream.saw("notes", &probe),
            served,
            "{header}: {}",
            response.status()
        );
    }
}

/// Test 5. Login CSRF: the attacker's valid code, delivered to the victim's
/// callback without the victim's state cookie, is never exchanged.
#[sqlx::test(migrations = "../../migrations")]
async fn an_attackers_code_is_not_exchanged_in_the_victims_browser(pool: PgPool) {
    let h = Harness::start(pool.clone()).await;
    let http = h.http();
    let (attacker_cookie, attacker_session) =
        control_plane_session(&pool, "attacker@example.com").await;

    let begun = http
        .get(format!("https://{NOTES}/"))
        .send()
        .await
        .expect("begin");
    let authorize = location(&begun);
    assert!(
        authorize.starts_with(&format!("https://{CONTROL_PLANE}/authorize?state=")),
        "{authorize}"
    );
    let issued = http
        .get(&authorize)
        .header(reqwest::header::COOKIE, &attacker_cookie)
        .send()
        .await
        .expect("authorize");
    let callback = location(&issued);
    assert!(
        callback.starts_with(&format!("https://{NOTES}/__clwd/callback?code=")),
        "{callback}"
    );

    let chrome = h.browser().await;
    chrome.open(&callback).await;

    let attacker_children: i64 =
        sqlx::query_scalar("select count(*) from app_sessions where parent_session_id = $1")
            .bind(attacker_session.as_uuid())
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(
        attacker_children, 0,
        "the attacker's code made no session in the victim's browser"
    );
}

/// Test 6. Signing out at the control plane ends the app-host session on the
/// very next app request.
#[sqlx::test(migrations = "../../migrations")]
async fn signing_out_ends_the_app_session_on_the_next_request(pool: PgPool) {
    let h = Harness::start(pool).await;
    let chrome = h.browser().await;
    let page = open_app(&chrome, NOTES, "/").await;
    let (_, secret) = cookie(&chrome, &page, NOTES, APP_SESSION).await.remove(0);
    let http = h.http();
    let with_session = |probe: &'static str| {
        http.get(format!("https://{NOTES}{probe}"))
            .header(reqwest::header::COOKIE, format!("{APP_SESSION}={secret}"))
            .send()
    };
    with_session("/echo?probe=before").await.expect("request");
    assert!(
        h.upstream.saw("notes", "/echo?probe=before"),
        "the session works before sign-out"
    );

    let cp = chrome
        .open(&format!("https://{CONTROL_PLANE}/openapi.json"))
        .await;
    let status: i64 = cp
        .evaluate("fetch('/auth/logout', {method: 'POST'}).then(r => r.status)")
        .await
        .expect("logout")
        .into_value()
        .expect("status");
    assert_eq!(status, 204);

    let after = with_session("/echo?probe=after").await.expect("request");
    assert!(
        !h.upstream.saw_anywhere("/echo?probe=after"),
        "nothing reached the app: {}",
        after.status()
    );
}

/// Test 7. App code never sees a platform cookie; its own cookies pass.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_never_receives_a_platform_cookie(pool: PgPool) {
    let h = Harness::start(pool).await;
    let chrome = h.browser().await;
    open_app(&chrome, NOTES, "/").await;
    chrome.open(&format!("https://{NOTES}/set-reserved")).await;
    let echo = chrome.open(&format!("https://{NOTES}/echo")).await;
    let seen = text(&echo).await;
    assert!(seen.contains("app_theme=dark"), "{seen}");
    for (app, header) in h.upstream.seen_cookies.lock().expect("lock").iter() {
        let lower = header.to_ascii_lowercase();
        assert!(
            !lower.contains("__host-clwd") && !lower.contains("__secure-clwd"),
            "{app} received {header}"
        );
    }
}

/// Test 8. No open redirect: `/authorize` goes only to the handshake's own
/// app, whatever else the URL says; a state the database does not hold goes
/// nowhere; a return path that would leave the host becomes the root.
#[sqlx::test(migrations = "../../migrations")]
async fn sign_in_redirects_only_to_the_apps_own_host(pool: PgPool) {
    let h = Harness::start(pool.clone()).await;
    let chrome = h.browser().await;
    open_app(&chrome, WIKI, "/").await;

    // First, with no session on notes yet, so this one goes through a
    // handshake: a return path that would leave the host becomes the root.
    let escaped = chrome.open(&format!("https://{NOTES}//{EVIL}/x")).await;
    assert_eq!(
        url(&escaped).await,
        format!("https://{NOTES}/"),
        "back to the app's root, on its own host"
    );

    let forged = chrome
        .open(&format!(
            "https://{CONTROL_PLANE}/authorize?state={}&host={EVIL}",
            "a".repeat(64)
        ))
        .await;
    assert!(
        url(&forged)
            .await
            .starts_with(&format!("https://{CONTROL_PLANE}/")),
        "{}",
        url(&forged).await
    );

    let begun = h
        .http()
        .get(format!("https://{WIKI}/"))
        .send()
        .await
        .expect("begin");
    let state = location(&begun).rsplit('=').next().unwrap_or("").to_owned();
    let tab = chrome
        .open(&format!(
            "https://{CONTROL_PLANE}/authorize?state={state}&host={EVIL}&redirect_uri=https%3A%2F%2F{EVIL}%2F"
        ))
        .await;
    assert!(
        url(&tab).await.starts_with(&format!("https://{WIKI}/")),
        "only the handshake's app: {}",
        url(&tab).await
    );
}

/// The cross-site entry: a link to an app clicked on another site — an email,
/// a chat — loads the app within a bounded number of redirects. `SameSite=Lax`
/// on the app-host session is what makes this work; `Strict` loops.
#[sqlx::test(migrations = "../../migrations")]
async fn a_link_from_another_site_opens_the_app(pool: PgPool) {
    let h = Harness::start(pool).await;
    let chrome = h.browser().await;
    open_app(&chrome, NOTES, "/").await;
    let link = chrome
        .open(&format!(
            "https://{EVIL}/link?to=https%3A%2F%2F{NOTES}%2Fshared"
        ))
        .await;
    let from = url(&link).await;
    link.evaluate("document.getElementById('go').click()")
        .await
        .expect("click");
    wait_to_leave(&link, &from).await;
    assert_eq!(url(&link).await, format!("https://{NOTES}/shared"));
    assert_eq!(app_name(&link).await, "notes", "{}", text(&link).await);
}

/// Two tabs, two handshakes at once: one state cookie overwrites the other,
/// and the loser restarts rather than dead-ending. Both end signed in.
#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_handshakes_both_end_signed_in(pool: PgPool) {
    let h = Harness::start(pool).await;
    let chrome = h.browser().await;
    open_app(&chrome, WIKI, "/").await;
    let (one, two) = (
        format!("https://{NOTES}/one"),
        format!("https://{NOTES}/two"),
    );
    let (a, b) = tokio::join!(chrome.open(&one), chrome.open(&two));
    for tab in [&a, &b] {
        assert_eq!(
            app_name(tab).await,
            "notes",
            "{}: {}",
            url(tab).await,
            text(tab).await
        );
    }
}

/// Four tabs of one app, opened at once while signed out: each handshake has
/// its own state cookie, so none invalidates another, and all four end signed
/// in (#83).
#[sqlx::test(migrations = "../../migrations")]
async fn four_concurrent_handshakes_all_end_signed_in(pool: PgPool) {
    let h = Harness::start(pool).await;
    let chrome = h.browser().await;
    open_app(&chrome, WIKI, "/").await;
    let urls: Vec<String> = ["one", "two", "three", "four"]
        .iter()
        .map(|p| format!("https://{NOTES}/{p}"))
        .collect();
    let tabs = futures::future::join_all(urls.iter().map(|u| chrome.open(u))).await;
    for tab in &tabs {
        assert_eq!(
            app_name(tab).await,
            "notes",
            "{}: {}",
            url(tab).await,
            text(tab).await
        );
    }
}

/// A browser's cookies for one app host: every `Set-Cookie` applied, a
/// `Max-Age=0` one deleting.
#[derive(Default)]
struct Jar(Vec<(String, String)>);

impl Jar {
    fn take(&mut self, response: &reqwest::Response) {
        for set in response.headers().get_all(reqwest::header::SET_COOKIE) {
            let Some((pair, attributes)) = set.to_str().ok().and_then(|c| c.split_once(';')) else {
                continue;
            };
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            self.0.retain(|(n, _)| n != name);
            if !attributes.contains("Max-Age=0") {
                self.0.push((name.to_owned(), value.to_owned()));
            }
        }
    }

    fn header(&self) -> String {
        self.0
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn states(&self) -> Vec<&str> {
        self.0
            .iter()
            .map(|(n, _)| n.as_str())
            .filter(|n| n.starts_with("__Host-clwd_state."))
            .collect()
    }

    fn get(&self, name: &str) -> Option<String> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    }
}

/// One browser's handshakes, driven by hand so the order is exact, with a
/// cookie jar that applies every `Set-Cookie` as a browser does:
///
/// - a fifth handshake in flight evicts the oldest state cookie;
/// - the evicted tab's callback restarts cleanly: a fresh handshake, not the
///   loop guard (and that restart, being a handshake, evicts the next oldest);
/// - every other tab completes, clearing only its own cookie;
/// - a tab whose cookie went while another tab signed in just goes to the app;
/// - a second callback for a completed state is refused, not redirected.
///
/// The loop guard's counter is dropped before the fifth: its window is a
/// minute and a state cookie lives ten, so a browser that began four
/// handshakes over a minute ago holds four state cookies and no counter.
#[sqlx::test(migrations = "../../migrations")]
async fn a_fifth_handshake_evicts_the_oldest_and_its_tab_restarts(pool: PgPool) {
    let h = Harness::start(pool.clone()).await;
    let http = h.http();
    let (cp_cookie, _) = control_plane_session(&pool, "tabs@example.com").await;
    let mut jar = Jar::default();
    let send = |url: String, jar: &Jar| {
        let mut request = http.get(url);
        if !jar.0.is_empty() {
            request = request.header(reqwest::header::COOKIE, jar.header());
        }
        request.send()
    };

    let mut authorizes = Vec::new();
    for tab in 0..5 {
        if tab == 4 {
            jar.0.retain(|(n, _)| n != "__Host-clwd_hs");
        }
        let begun = send(format!("https://{NOTES}/tab{tab}"), &jar)
            .await
            .expect("begin");
        let authorize = location(&begun);
        assert!(
            authorize.contains("/authorize?state="),
            "tab {tab}: {authorize}"
        );
        jar.take(&begun);
        authorizes.push(authorize);
    }
    let cookie_of = |authorize: &str| format!("__Host-clwd_state.{}", &state_of(authorize)[..16]);
    assert_eq!(jar.states().len(), 4, "at most four handshakes in flight");
    assert!(
        !jar.states().contains(&cookie_of(&authorizes[0]).as_str()),
        "the oldest handshake was not the one evicted"
    );

    // Each tab reaches the control plane, which sends it back with a code.
    let mut callbacks = Vec::new();
    for authorize in &authorizes {
        let issued = http
            .get(authorize)
            .header(reqwest::header::COOKIE, &cp_cookie)
            .send()
            .await
            .expect("authorize");
        callbacks.push(location(&issued));
    }

    // The evicted tab restarts, and its restart evicts the next oldest (tab 1).
    let restarted = send(callbacks[0].clone(), &jar)
        .await
        .expect("evicted callback");
    let fresh = location(&restarted);
    assert!(
        fresh.contains("/authorize?state="),
        "the evicted tab did not restart: {fresh}"
    );
    jar.take(&restarted);
    assert!(!jar.states().contains(&cookie_of(&authorizes[1]).as_str()));

    // Tabs 2 to 4 complete, each clearing only its own cookie.
    let replayable = jar.get(&cookie_of(&authorizes[3])).expect("tab 3's cookie");
    for tab in 2..5 {
        let before = jar.states().len();
        let done = send(callbacks[tab].clone(), &jar).await.expect("callback");
        assert_eq!(location(&done), format!("/tab{tab}"), "tab {tab}");
        jar.take(&done);
        assert!(jar.get(APP_SESSION).is_some(), "tab {tab} got no session");
        assert_eq!(
            jar.states().len(),
            before - 1,
            "tab {tab} cleared more than its own"
        );
        assert!(!jar.states().contains(&cookie_of(&authorizes[tab]).as_str()));
    }

    // Tab 1's cookie went, but the browser is signed in now: to the app.
    let late = send(callbacks[1].clone(), &jar)
        .await
        .expect("late callback");
    assert_eq!(location(&late), "/", "tab 1 did not just go to the app");

    // Tab 0's restart completes too.
    let issued = http
        .get(&fresh)
        .header(reqwest::header::COOKIE, &cp_cookie)
        .send()
        .await
        .expect("authorize");
    let done = send(location(&issued), &jar)
        .await
        .expect("restarted callback");
    assert_eq!(
        location(&done),
        "/",
        "tab 0's restart returned somewhere else"
    );
    jar.take(&done);
    assert!(
        jar.states().is_empty(),
        "a state cookie outlived its handshake"
    );

    // A second callback for tab 3's completed state, its cookie replayed:
    // refused, never another redirect.
    let replayed = http
        .get(&callbacks[3])
        .header(
            reqwest::header::COOKIE,
            format!("{}={replayable}", cookie_of(&authorizes[3])),
        )
        .send()
        .await
        .expect("replay");
    let body: serde_json::Value = replayed.json().await.expect("an envelope");
    assert_eq!(body["code"], "gateway.sign_in_failed");
}

/// Only a valid app-host session for the requested app reaches the hop:
/// none, a session for another app, a forged one — each leaves the count at
/// zero. And the hop's target is the resolved app, whatever the request says.
#[sqlx::test(migrations = "../../migrations")]
async fn only_a_valid_session_for_this_app_reaches_the_upstream(pool: PgPool) {
    let h = Harness::start(pool).await;
    let chrome = h.browser().await;
    let page = open_app(&chrome, NOTES, "/").await;
    let (_, notes_secret) = cookie(&chrome, &page, NOTES, APP_SESSION).await.remove(0);
    let http = h.http();
    for (i, (host, cookie)) in [
        (NOTES, String::new()),
        (WIKI, format!("{APP_SESSION}={notes_secret}")),
        (NOTES, format!("{APP_SESSION}={}", "f".repeat(64))),
    ]
    .into_iter()
    .enumerate()
    {
        let probe = format!("/echo?probe=invariant-{i}");
        let response = http
            .get(format!("https://{host}{probe}"))
            .header(reqwest::header::COOKIE, cookie.clone())
            .send()
            .await
            .expect("request");
        assert!(
            !h.upstream.saw_anywhere(&probe),
            "{host} with {cookie:?} reached the app: {}",
            response.status()
        );
    }

    let probe = format!("/echo?probe=target&upstream={WIKI}");
    http.get(format!("https://{NOTES}{probe}"))
        .header(
            reqwest::header::COOKIE,
            format!("{APP_SESSION}={notes_secret}"),
        )
        .header("x-forwarded-host", WIKI)
        .header("x-clwd-upstream", "127.0.0.1:1")
        .send()
        .await
        .expect("request");
    assert!(
        h.upstream.saw("notes", &probe),
        "the valid request reached its app"
    );
    assert!(
        !h.upstream.saw("wiki", &probe),
        "the target is the resolved app, not the request's"
    );
}

/// Codes and states never reach a log line, on either server, across a full
/// handshake at TRACE.
#[sqlx::test(migrations = "../../migrations")]
async fn no_code_or_state_is_ever_logged(pool: PgPool) {
    let h = Harness::start(pool.clone()).await;
    let http = h.http();
    let (cp_cookie, _) = control_plane_session(&pool, "logs@example.com").await;

    let begun = http
        .get(format!("https://{NOTES}/"))
        .send()
        .await
        .expect("begin");
    let (state_name, state_cookie) = state_cookie_set(&begun).expect("state cookie");
    let issued = http
        .get(location(&begun))
        .header(reqwest::header::COOKIE, &cp_cookie)
        .send()
        .await
        .expect("authorize");
    let callback = location(&issued);
    let code = callback
        .split("code=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("code")
        .to_owned();
    let done = http
        .get(&callback)
        .header(
            reqwest::header::COOKIE,
            format!("{state_name}={state_cookie}"),
        )
        .send()
        .await
        .expect("callback");
    let session = set_cookie_value(&done, APP_SESSION).expect("a session was issued");

    let text = logs().text();
    assert!(
        !text.is_empty(),
        "the capture saw nothing; it would pass by not looking"
    );
    for (what, value) in [
        ("code", &code),
        ("state", &state_of(&location(&begun))),
        ("session", &session),
    ] {
        assert!(!text.contains(value.as_str()), "a {what} reached the logs");
    }
}

/// The interim access rule (#12 replaces it): a signed-in visitor who is not a
/// member of the app's org gets `gateway.not_a_member`, and nothing reaches the
/// hop — not the page, not anything after it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_reaches_no_app_code(pool: PgPool) {
    let h = Harness::start(pool).await;
    let chrome = h.browser().await;
    open_app(&chrome, NOTES, "/").await;
    let page = chrome
        .open(&format!("https://{ATTACKER_APP}/probe-non-member"))
        .await;
    let body = text(&page).await;
    assert!(body.contains("gateway.not_a_member"), "{body}");
    assert!(
        !h.upstream.saw_anywhere("/probe-non-member"),
        "a non-member's request reached the hop"
    );
    assert!(
        h.upstream
            .seen_paths
            .lock()
            .expect("lock")
            .iter()
            .all(|(app, _)| *app != "page"),
        "no request of any kind reached the non-member's app"
    );
}

// ======================================================================
// Identity injection (#11): the real worker, running the whoami fixture.
//
// Each test asserts what the app saw — the fixture echoes its caller and
// every header it received — or how many times app code ran.
// ======================================================================

/// A visitor made directly in the database, the way sign-in and the exchange
/// make one: a user, a control-plane session, their pairwise subject for an
/// app in `acme`, and an app-host session for it.
struct Visitor {
    /// The `Cookie` pair for the app-host session.
    cookie: String,
    /// The subject `notes` should see.
    subject: String,
    /// The control-plane session the app session hangs off.
    parent: control_plane::ids::SessionId,
    /// The control-plane session's `Cookie` pair, for signing out.
    cp_cookie: String,
    /// The app-host session secret, for a gateway driven directly.
    secret: String,
    app_id: uuid::Uuid,
    user_id: uuid::Uuid,
}

async fn visitor(pool: &PgPool, email: &str, member: bool) -> Visitor {
    visitor_of(pool, "notes", email, member).await
}

async fn visitor_of(pool: &PgPool, app: &str, email: &str, member: bool) -> Visitor {
    let user = control_plane::db::create_user(pool, email)
        .await
        .expect("user");
    let issued = session::issue(pool, &cookie_key(), user.id)
        .await
        .expect("issue")
        .expect("a session");
    let parent = issued.id;
    let cp_cookie = issued
        .set_cookie
        .split(';')
        .next()
        .expect("a name=value pair")
        .to_owned();
    let app: uuid::Uuid = sqlx::query_scalar(
        "select a.id from apps a join orgs o on o.id = a.org_id where o.slug = 'acme' and a.name = $1",
    )
    .bind(app)
    .fetch_one(pool)
    .await
    .expect("the app");
    let secret: String = rand::random::<[u8; 32]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    use sha2::Digest as _;
    sqlx::query(
        "insert into app_sessions (id, parent_session_id, app_id, secret_sha256, expires_at)
         values ($1, $2, $3, $4, now() + interval '1 hour')",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(parent.as_uuid())
    .bind(app)
    .bind(sha2::Sha256::digest(secret.as_bytes()).to_vec())
    .execute(pool)
    .await
    .expect("app session");
    let subject: String = sqlx::query_scalar(
        "insert into app_subjects (app_id, user_id) values ($1, $2) returning subject::text",
    )
    .bind(app)
    .bind(user.id.as_uuid())
    .fetch_one(pool)
    .await
    .expect("subject");
    if member {
        sqlx::query(
            "insert into org_members (org_id, user_id, joined_via)
             select id, $1, 'claimant' from orgs where slug = 'acme'",
        )
        .bind(user.id.as_uuid())
        .execute(pool)
        .await
        .expect("member");
    }
    Visitor {
        cookie: format!("{APP_SESSION}={secret}"),
        subject,
        parent,
        cp_cookie,
        secret,
        app_id: app,
        user_id: user.id.as_uuid(),
    }
}

/// `GET https://notes…{path}` with `cookie` and `extra` headers: the status
/// and, when the app answered, its JSON.
async fn on_notes(
    client: &reqwest::Client,
    path: &str,
    cookie: &str,
    extra: &[(&str, &str)],
) -> (reqwest::StatusCode, serde_json::Value) {
    on_app(client, NOTES, path, cookie, extra).await
}

async fn on_app(
    client: &reqwest::Client,
    host: &str,
    path: &str,
    cookie: &str,
    extra: &[(&str, &str)],
) -> (reqwest::StatusCode, serde_json::Value) {
    let mut request = client
        .get(format!("https://{host}{path}"))
        .header(reqwest::header::COOKIE, cookie);
    for (name, value) in extra {
        request = request.header(*name, *value);
    }
    let response = request.send().await.expect("the gateway answers");
    let status = response.status();
    let json = response.json().await.unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn invocations(h: &Harness) -> u64 {
    h.worker.as_ref().expect("a worker harness").invocations()
}

/// What the fixture reports it received, as `(lowercase name, value)` pairs.
fn echoed_headers(json: &serde_json::Value) -> Vec<(String, String)> {
    json["headers"]
        .as_array()
        .expect("headers")
        .iter()
        .map(|pair| {
            (
                pair[0].as_str().unwrap_or("").to_ascii_lowercase(),
                pair[1].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect()
}

/// Test 1, the MVP exit: a signed-in visitor gets `hello <their verified
/// email>` from an app with no auth code in it, in a real browser.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_greets_the_signed_in_visitor_by_verified_email(pool: PgPool) {
    let h = Harness::with_worker(pool).await;
    let chrome = h.browser().await;
    let page = chrome.open(&format!("https://{NOTES}/")).await;
    let mut seen = String::new();
    for _ in 0..50 {
        seen = text(&page).await;
        if seen.starts_with("hello") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(
        seen.trim(),
        format!("hello {}", support::EMAIL),
        "{}",
        url(&page).await
    );
    assert!(invocations(&h) >= 1);
}

/// Test 2: a client-sent identity header is ignored. The app's caller is the
/// session's, and none of the forged headers reach it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_forged_identity_header_changes_nothing(pool: PgPool) {
    let h = Harness::with_worker(pool.clone()).await;
    let real = visitor(&pool, "real@example.com", true).await;
    let other = visitor(&pool, "other@example.com", true).await;
    let forged: &[(&str, &str)] = &[
        ("x-clwd-caller", &other.subject),
        ("x-clwd-subject", &other.subject),
        ("x-clwd-email", "other@example.com"),
        ("forwarded", "for=6.6.6.6"),
        ("x-forwarded-for", "6.6.6.6"),
        ("x-forwarded-host", "evil.example"),
        ("x-forwarded-proto", "http"),
        ("x-real-ip", "6.6.6.6"),
        ("x-client-ip", "6.6.6.6"),
        ("true-client-ip", "6.6.6.6"),
        ("cf-connecting-ip", "6.6.6.6"),
    ];
    let (status, json) = on_notes(&h.http(), "/whoami", &real.cookie, forged).await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["caller"]["subject"], real.subject.as_str());
    assert_eq!(json["caller"]["email"], "real@example.com");
    let headers = echoed_headers(&json);
    for (name, _) in forged {
        assert!(
            headers.iter().all(|(n, _)| n != name),
            "{name} reached the app: {headers:?}"
        );
    }
    assert!(
        headers.iter().all(|(_, v)| !v.contains(&other.subject)),
        "the forged subject reached the app"
    );
}

/// Test 3: no platform cookie reaches app code, asserted at the wasm boundary
/// with the fixture's echo. The app's own cookie does.
#[sqlx::test(migrations = "../../migrations")]
async fn no_platform_cookie_reaches_the_wasm_boundary(pool: PgPool) {
    let h = Harness::with_worker(pool.clone()).await;
    let v = visitor(&pool, "v@example.com", true).await;
    let cookies = format!(
        "{}; __Host-clwd_session=cp; __Secure-clwd_session=apex; __Host-clwd_state=st; app_theme=dark",
        v.cookie
    );
    let (status, json) = on_notes(&h.http(), "/whoami", &cookies, &[]).await;
    assert_eq!(status, 200, "{json}");
    let cookie: String = echoed_headers(&json)
        .into_iter()
        .filter(|(n, _)| n == "cookie")
        .map(|(_, v)| v.to_ascii_lowercase())
        .collect();
    assert!(cookie.contains("app_theme=dark"), "{cookie}");
    assert!(
        !cookie.contains("__host-clwd") && !cookie.contains("__secure-clwd"),
        "a platform cookie reached the app: {cookie}"
    );
}

/// How many of test 4's requests are in flight at once: 16× the worker's
/// threads, so invocations overlap throughout, without queuing all 256
/// session checks at once behind the control plane, which shares this test's
/// single thread. (#90 measured 16 as well: the refusals continued, with the
/// pool idle at the time, so concurrency is not their cause.)
const IN_FLIGHT: usize = 64;

/// Test 4: concurrent requests from different visitors each see only their
/// own caller. 64 visitors, 4 requests each, 256 in all, [`IN_FLIGHT`] at a
/// time: overlapping invocations on a handful of worker threads. A caller kept anywhere
/// across invocations shows up as the wrong subject, and one overwritten
/// mid-request as `caller_after` disagreeing with `caller`.
#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_visitors_each_see_only_themselves(pool: PgPool) {
    let h = Harness::with_worker(pool.clone()).await;
    let mut visitors = Vec::new();
    for i in 0..64 {
        visitors.push(visitor(&pool, &format!("v{i}@example.com"), true).await);
    }
    let client = h.http();
    let requests = visitors
        .iter()
        .flat_map(|v| std::iter::repeat_n(v, 4))
        .map(|v| {
            let client = client.clone();
            async move { (v, on_notes(&client, "/whoami", &v.cookie, &[]).await) }
        });
    use futures::StreamExt as _;
    let answers: Vec<_> = futures::stream::iter(requests)
        .buffer_unordered(IN_FLIGHT)
        .collect()
        .await;
    assert_eq!(answers.len(), 256);
    if answers.iter().any(|(_, (status, _))| *status != 200) {
        support::explain_refusals(&pool).await;
    }
    for (v, (status, json)) in answers {
        assert_eq!(status, 200, "{json}");
        assert_eq!(json["caller"]["subject"], v.subject.as_str(), "{json}");
        assert_eq!(json["caller_after"], json["caller"], "{json}");
    }
}

/// Test 5: revoking the parent session runs nothing on the next request.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_session_runs_nothing(pool: PgPool) {
    let h = Harness::with_worker(pool.clone()).await;
    let v = visitor(&pool, "v@example.com", true).await;
    let client = h.http();
    let (status, _) = on_notes(&client, "/whoami", &v.cookie, &[]).await;
    assert_eq!(status, 200, "positive control: the session works");
    // The API revoke path, whose bound is zero: the next request is refused
    // with no wait of the test's own. (A raw SQL revoke's 3-second bound has
    // its own test.)
    sign_out(&client, &v).await;
    let before = invocations(&h);
    let (status, _) = on_notes(&client, "/whoami", &v.cookie, &[]).await;
    assert_ne!(status, 200);
    assert_eq!(invocations(&h), before, "a revoked session ran app code");
}

/// Test 6: a signed-in non-member of the app's org runs nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_runs_nothing(pool: PgPool) {
    let h = Harness::with_worker(pool.clone()).await;
    let v = visitor(&pool, "outsider@example.net", false).await;
    let (status, json) = on_notes(&h.http(), "/whoami", &v.cookie, &[]).await;
    assert_eq!(status, 403, "{json}");
    assert_eq!(json["code"], "gateway.not_a_member");
    assert_eq!(invocations(&h), 0);
}

/// Store `bundle` and make it the newest ready version of `wiki`. Not `notes`:
/// the harness's startup probe has the gateway's route cache holding notes'
/// first version, and wiki has never been resolved.
async fn publish_to_wiki(h: &Harness, bundle: bytes::Bytes) -> clwd_bundle::BundleRef {
    let validated = builder::validate(bundle).expect("validates");
    h.artifacts.put(&validated).await.expect("stored");
    sqlx::query(
        "insert into app_versions (id, app_id, digest, state)
         select $1, a.id, $2, 'ready' from apps a join orgs o on o.id = a.org_id
          where o.slug = 'acme' and a.name = 'wiki'",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(validated.digest().to_string())
    .execute(&h.pool)
    .await
    .expect("version");
    *validated.digest()
}

/// Test 7: an artifact whose bytes no longer match its digest is refused
/// before anything is instantiated.
#[sqlx::test(migrations = "../../migrations")]
async fn a_tampered_artifact_is_refused_before_it_runs(pool: PgPool) {
    let h = Harness::with_worker(pool.clone()).await;
    let v = visitor_of(&pool, "wiki", "v@example.com", true).await;
    // A version of its own (another cpu budget, so another digest), so the
    // other apps' artifact is untouched.
    let wasm = support::WHOAMI.to_vec();
    let encoded = clwd_bundle::build(
        clwd_bundle::Runtime::Wasm,
        "app.wasm",
        clwd_bundle::Capabilities {
            version: 1,
            egress: vec![],
            secrets: vec![],
            storage_namespaces: vec![],
            limits: clwd_bundle::Limits {
                cpu_ms: 4_999,
                memory_mb: 128,
            },
        },
        vec![clwd_bundle::File {
            path: "app.wasm".into(),
            data: wasm,
            executable: false,
        }],
    )
    .expect("encodes");
    let digest = publish_to_wiki(&h, bytes::Bytes::from(encoded.bytes)).await;

    let mut stored = h
        .artifacts
        .get_bytes(&digest)
        .await
        .expect("stored")
        .to_vec();
    let middle = stored.len() / 2;
    stored[middle] ^= 0x01;
    let recompressed = zstd::encode_all(stored.as_slice(), 3).expect("compress");
    h.operator
        .write(builder::ArtifactKey::bundle(&digest).as_str(), recompressed)
        .await
        .expect("tamper");

    let (status, json) = on_app(&h.http(), WIKI, "/whoami", &v.cookie, &[]).await;
    assert_eq!(status, 502, "{json}");
    assert_eq!(json["code"], "gateway.app_unreachable");
    assert_eq!(invocations(&h), 0, "a tampered artifact ran");
}

/// The worker is the authoritative egress refusal: a version whose manifest
/// grants egress (stored around publish, which refuses it too) never runs.
#[sqlx::test(migrations = "../../migrations")]
async fn the_worker_refuses_a_bundle_that_grants_egress(pool: PgPool) {
    let h = Harness::with_worker(pool.clone()).await;
    let v = visitor_of(&pool, "wiki", "v@example.com", true).await;
    publish_to_wiki(
        &h,
        support::bundle_of(support::WHOAMI, &["169.254.169.254"]),
    )
    .await;
    let (status, json) = on_app(&h.http(), WIKI, "/whoami", &v.cookie, &[]).await;
    assert_eq!(status, 502, "{json}");
    assert_eq!(invocations(&h), 0, "a bundle granting egress ran");
}

/// A worker is untrusted: one that answers with a platform `Set-Cookie`, an
/// oversized frame, a malformed frame or an oversized body is stripped or
/// refused, and the gateway keeps serving.
#[sqlx::test(migrations = "../../migrations")]
async fn a_misbehaving_worker_is_contained(pool: PgPool) {
    use shared::hop::{self, RequestHead, ResponseHead};
    use tokio::io::AsyncWriteExt as _;

    // Removed when the test ends, like every path a test makes (#90).
    let socket = support::Scratch::socket();
    let listener = tokio::net::UnixListener::bind(socket.path()).expect("bind");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let Ok((head, _)) = hop::read_frame::<_, RequestHead>(&mut stream).await else {
                    return;
                };
                match head.path_and_query.as_str() {
                    "/cookie" => {
                        let answer = ResponseHead::answer(
                            200,
                            vec![
                                (
                                    "set-cookie".into(),
                                    b"__Host-clwd_app_session=planted; Path=/; Secure".to_vec(),
                                ),
                                ("set-cookie".into(), b"theme=dark; Path=/".to_vec()),
                            ],
                        );
                        let _ = hop::write_frame(&mut stream, &answer, b"ok").await;
                    }
                    "/oversized" => {
                        let _ = stream.write_all(&(hop::MAX_HEAD + 1).to_be_bytes()).await;
                    }
                    // Complete, well-formed frames that break a cap: a gateway
                    // without the cap would read them whole and answer 200.
                    "/huge-body" => {
                        let answer = serde_json::to_vec(&ResponseHead::answer(200, vec![]))
                            .expect("encodes");
                        let _ = stream.write_all(&(answer.len() as u32).to_be_bytes()).await;
                        let _ = stream.write_all(&answer).await;
                        let _ = stream.write_all(&(hop::MAX_BODY + 1).to_be_bytes()).await;
                        let body = vec![b'x'; usize::try_from(hop::MAX_BODY + 1).expect("fits")];
                        let _ = stream.write_all(&body).await;
                    }
                    "/many-headers" => {
                        let headers = (0..=hop::MAX_HEADERS)
                            .map(|i| (format!("x-h{i}"), b"1".to_vec()))
                            .collect();
                        let answer = serde_json::to_vec(&ResponseHead::answer(200, headers))
                            .expect("encodes");
                        let _ = stream.write_all(&(answer.len() as u32).to_be_bytes()).await;
                        let _ = stream.write_all(&answer).await;
                        let _ = stream.write_all(&0u64.to_be_bytes()).await;
                    }
                    _ => {
                        let _ = stream.write_all(&5u32.to_be_bytes()).await;
                        let _ = stream.write_all(b"{nope").await;
                        let _ = stream.write_all(&0u64.to_be_bytes()).await;
                    }
                }
            });
        }
    });

    let h = Harness::with_hop(
        pool.clone(),
        std::sync::Arc::new(gateway::worker::WorkerUpstream::new(
            socket.path(),
            support::my_uid(),
        )),
    )
    .await;
    let v = visitor(&pool, "v@example.com", true).await;
    let client = h.http();
    let set_cookies = |response: &reqwest::Response| -> Vec<String> {
        response
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_owned))
            .collect()
    };

    for _ in 0..2 {
        let response = client
            .get(format!("https://{NOTES}/cookie"))
            .header(reqwest::header::COOKIE, &v.cookie)
            .send()
            .await
            .expect("answers");
        assert_eq!(response.status(), 200);
        let cookies = set_cookies(&response);
        assert!(
            cookies.iter().any(|c| c.starts_with("theme=dark")),
            "{cookies:?}"
        );
        assert!(
            cookies.iter().all(|c| !c.contains("planted")),
            "a platform cookie from the worker reached the browser: {cookies:?}"
        );
        for path in ["/oversized", "/huge-body", "/many-headers", "/malformed"] {
            let (status, json) = on_notes(&client, path, &v.cookie, &[]).await;
            assert_eq!(status, 502, "{path}: {json}");
            assert_eq!(json["code"], "gateway.app_unreachable", "{path}");
        }
    }
}

// ======================================================================
// #12: the authorization cache. Each test warms the cache first and checks
// the warm request really was a hit, so what it proves is invalidation, not
// a miss. Changes made outside the API wait on `settle`, which is the revoke
// API's own wait: the contract is "within the lease" for those.
// ======================================================================

/// Wait until no gateway can serve a decision older than the newest change.
async fn settle(pool: &PgPool) {
    let seq = control_plane::relay::latest(pool).await.expect("latest");
    control_plane::relay::converged(pool, seq)
        .await
        .expect("every gateway converges");
}

fn hits(h: &Harness) -> u64 {
    h.authz
        .stats()
        .hits
        .load(std::sync::atomic::Ordering::SeqCst)
}

/// Two requests as `v`; the second must be a cache hit.
async fn warm(h: &Harness, client: &reqwest::Client, v: &Visitor, host: &str) {
    let (status, json) = on_app(client, host, "/whoami", &v.cookie, &[]).await;
    assert_eq!(status, 200, "positive control: the session works: {json}");
    let before = hits(h);
    let (status, json) = on_app(client, host, "/whoami", &v.cookie, &[]).await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(hits(h), before + 1, "the warm request was not a cache hit");
}

/// `POST /auth/logout` as `v`, the API revoke path.
async fn sign_out(client: &reqwest::Client, v: &Visitor) {
    let response = client
        .post(format!("https://{CONTROL_PLANE}/auth/logout"))
        .header(reqwest::header::COOKIE, &v.cp_cookie)
        .header("sec-fetch-site", "same-origin")
        .send()
        .await
        .expect("the control plane answers");
    assert_eq!(response.status(), 204);
}

/// Refused, and no app code ran.
async fn refused(h: &Harness, client: &reqwest::Client, v: &Visitor, host: &str, case: &str) {
    let before = invocations(h);
    let (status, json) = on_app(client, host, "/whoami", &v.cookie, &[]).await;
    assert_ne!(status, 200, "{case}: a stale allow was served: {json}");
    assert_eq!(invocations(h), before, "{case}: app code ran");
}

/// Test 1: signing out (the API path) denies the very next request, from a
/// warm cache, with no wait of the test's own.
#[sqlx::test(migrations = "../../migrations")]
async fn signing_out_denies_the_next_request_from_a_warm_cache(pool: PgPool) {
    let h = Harness::with_worker(pool.clone()).await;
    let v = visitor(&pool, "v@example.com", true).await;
    let client = h.http();
    warm(&h, &client, &v, NOTES).await;
    sign_out(&client, &v).await;
    refused(&h, &client, &v, NOTES, "sign-out").await;
}

/// What a staleness case changes, and what the next request must show.
enum Expect {
    Refused,
    /// Allowed, with this field of the caller changed.
    Changed(&'static str),
}

/// Test 2: every decision input, changed directly in SQL with a warm cache.
/// The cases are keyed by table and must cover exactly
/// `control_plane::authz::INPUTS`, so adding an input without a case here
/// fails this test. Run in one harness; app and org deletion last.
#[sqlx::test(migrations = "../../migrations")]
async fn every_decision_input_invalidates_a_warm_cache(pool: PgPool) {
    let h = Harness::with_worker(pool.clone()).await;
    let client = h.http();
    let cases: &[(&str, &str, &str, Expect)] = &[
        (
            "app_sessions",
            "notes",
            "update app_sessions set expires_at = now() where parent_session_id = $1",
            Expect::Refused,
        ),
        (
            "sessions",
            "notes",
            "update sessions set revoked_at = now() where id = $1",
            Expect::Refused,
        ),
        (
            "users",
            "notes",
            "update users set deleted_at = now() where id = (select user_id from sessions where id = $1)",
            Expect::Refused,
        ),
        (
            "users",
            "notes",
            "update users set email = 'renamed@example.com' where id = (select user_id from sessions where id = $1)",
            Expect::Changed("email"),
        ),
        (
            "org_members",
            "notes",
            "delete from org_members where user_id = (select user_id from sessions where id = $1)",
            Expect::Refused,
        ),
        (
            "app_subjects",
            "notes",
            "update app_subjects set subject = gen_random_uuid() where user_id = (select user_id from sessions where id = $1)",
            Expect::Changed("subject"),
        ),
        (
            "apps",
            "notes",
            "update apps set deleted_at = now() where name = 'notes' and $1::uuid is not null",
            Expect::Refused,
        ),
        (
            "orgs",
            "wiki",
            "update orgs set deleted_at = now() where slug = 'acme' and $1::uuid is not null",
            Expect::Refused,
        ),
    ];
    let covered: std::collections::BTreeSet<&str> = cases.iter().map(|c| c.0).collect();
    let inputs: std::collections::BTreeSet<&str> = control_plane::authz::INPUTS
        .iter()
        .map(|i| i.table)
        .collect();
    assert_eq!(covered, inputs, "a decision input has no staleness case");

    for (i, (table, app, change, expect)) in cases.iter().enumerate() {
        let v = visitor_of(&pool, app, &format!("v{i}@example.com"), true).await;
        let host = if *app == "wiki" { WIKI } else { NOTES };
        warm(&h, &client, &v, host).await;
        let (_, before) = on_app(&client, host, "/whoami", &v.cookie, &[]).await;
        sqlx::query(*change)
            .bind(v.parent.as_uuid())
            .execute(&pool)
            .await
            .expect(table);
        settle(&pool).await;
        match expect {
            Expect::Refused => refused(&h, &client, &v, host, table).await,
            Expect::Changed(field) => {
                let (status, after) = on_app(&client, host, "/whoami", &v.cookie, &[]).await;
                assert_eq!(status, 200, "{table}: {after}");
                assert_ne!(
                    after["caller"][field], before["caller"][field],
                    "{table}: the cached {field} was served after it changed"
                );
            }
        }
    }
}

/// Test 3: a revocation typed straight into Postgres, bypassing every code
/// path, still reaches a warm cache. This is what proves the triggers rather
/// than the application's write paths.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revocation_typed_into_psql_reaches_a_warm_cache(pool: PgPool) {
    let h = Harness::with_worker(pool.clone()).await;
    let v = visitor(&pool, "v@example.com", true).await;
    let client = h.http();
    warm(&h, &client, &v, NOTES).await;
    // What an operator's psql session does: a transaction, a statement, a
    // commit. No control-plane function is called.
    let mut psql = pool.begin().await.expect("begin");
    sqlx::query("update sessions set revoked_at = now() where id = $1")
        .bind(v.parent.as_uuid())
        .execute(&mut *psql)
        .await
        .expect("revoke by hand");
    psql.commit().await.expect("commit");
    settle(&pool).await;
    refused(&h, &client, &v, NOTES, "psql").await;
}

/// Test 4: a dropped stream fails closed. Cut it (and keep it cut), revoke
/// with no stream to carry the news, and request at once, inside the lease:
/// refused, because a gateway without a stream bypasses its cache.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dropped_stream_fails_closed(pool: PgPool) {
    let h = Harness::with_worker(pool.clone()).await;
    let v = visitor(&pool, "v@example.com", true).await;
    let client = h.http();
    warm(&h, &client, &v, NOTES).await;
    h.stream_proxy.cut();
    support::wait_until("the gateway sees its stream drop", || {
        h.authz
            .stats()
            .disconnects
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1
    })
    .await;
    sqlx::query("update sessions set revoked_at = now() where id = $1")
        .bind(v.parent.as_uuid())
        .execute(&pool)
        .await
        .expect("revoke");
    refused(&h, &client, &v, NOTES, "dropped stream").await;
}

/// A disabled trigger is a revocation that would never be announced, so the
/// relay stops heartbeating and the gateway stops caching.
#[sqlx::test(migrations = "../../migrations")]
async fn a_disabled_trigger_sends_the_gateway_to_bypass(pool: PgPool) {
    let h = Harness::with_worker(pool.clone()).await;
    let v = visitor(&pool, "v@example.com", true).await;
    let client = h.http();
    warm(&h, &client, &v, NOTES).await;
    sqlx::query("alter table org_members disable trigger authz_del")
        .execute(&pool)
        .await
        .expect("disable");
    support::wait_until("the gateway stops caching", || !h.authz.is_caching()).await;
    sqlx::query("delete from org_members where user_id = $1")
        .bind(v.user_id)
        .execute(&pool)
        .await
        .expect("remove the member, unannounced");
    refused(&h, &client, &v, NOTES, "disabled trigger").await;
    sqlx::query("alter table org_members enable trigger authz_del")
        .execute(&pool)
        .await
        .expect("enable");
}

/// Test 7: with two gateways, a revoke returns only after both have dropped
/// the entry; a gateway that never acks is waited out to its lease, and is
/// in bypass when the revoke returns.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoke_waits_for_every_gateway(pool: PgPool) {
    let h = Harness::with_worker(pool.clone()).await;
    let client = h.http();
    // Gateway B: a second cache on the real control plane, through a proxy
    // that can hold its acks.
    let proxy = support::StreamProxy::start(
        h.internal_base
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .expect("internal port"),
    )
    .await;
    let b = Arc::new(gateway::authz::Authz::new(Arc::new(
        gateway::signin::SigninClient::new(h.internal_base.clone(), support::INTERNAL_SECRET)
            .expect("client"),
    )));
    h.follow(b.clone(), &proxy.base());
    support::wait_until("gateway B is caching", || b.is_caching()).await;
    let on_b = |v: &Visitor| {
        let (b, secret, app) = (b.clone(), v.secret.clone(), v.app_id.to_string());
        async move {
            b.authorize(&gateway::signin::AppSession::new(&secret), &app)
                .await
                .expect("reachable")
                .is_some_and(|c| c.decision.is_allow())
        }
    };

    // Acks held, then released: the revoke returns after the release. (This
    // half proves the ordering holds; it cannot catch a revoke that skips the
    // wait, because such a revoke races B's apply. The never-acks half below
    // is the deterministic detector: it catches that every time.)
    let v = visitor(&pool, "v@example.com", true).await;
    warm(&h, &client, &v, NOTES).await;
    assert!(on_b(&v).await && on_b(&v).await);
    proxy.hold_acks().await;
    let before = h.relay.current();
    let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let revoke = {
        let (client, cp_cookie, released, b) = (
            client.clone(),
            v.cp_cookie.clone(),
            released.clone(),
            b.clone(),
        );
        tokio::spawn(async move {
            let response = client
                .post(format!("https://{CONTROL_PLANE}/auth/logout"))
                .header(reqwest::header::COOKIE, cp_cookie)
                .header("sec-fetch-site", "same-origin")
                .send()
                .await
                .expect("answers");
            // B's state at the moment the revoke returned.
            (
                response.status(),
                released.load(std::sync::atomic::Ordering::SeqCst),
                b.is_caching(),
            )
        })
    };
    // The revocation is committed, and B has either applied it (its ack is
    // what is held) or is in bypass: under load its follower can stall behind
    // the held ack until its lease lapses, and bypass is the contract holding
    // (seen once in 50 suite runs: applied one short, lease lapsed, refused).
    // Bounded like `wait_until`, but a timeout says what state everything was
    // in, so a recurrence explains itself: had the revoke returned, was B in
    // bypass, and was a request to B refused.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !(h.relay.current() > before && (b.applied() >= h.relay.current() || !b.is_caching())) {
        if std::time::Instant::now() > deadline {
            let returned = revoke.is_finished();
            let state = b.describe();
            let stats = b.stats().snapshot();
            let served = on_b(&v).await;
            panic!(
                "timed out waiting: B applies the revocation. relay.current={} before={before} \
                 revoke_returned={returned} B: {state} B_served_the_revoked_session={served} \
                 B stats: {stats:?}",
                h.relay.current()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    // Applied or in bypass, B refuses the revoked session.
    assert!(
        !on_b(&v).await,
        "gateway B served the revoked session: {}",
        b.describe()
    );
    released.store(true, std::sync::atomic::Ordering::SeqCst);
    proxy.release();
    let (status, after_release, b_caching) = revoke.await.expect("joined");
    assert_eq!(status, 204);
    // The contract at return: B has applied the revocation (its ack was let
    // through and recorded), or B's own lease has lapsed, so it is in bypass.
    assert!(
        after_release || !b_caching,
        "the revoke returned while gateway B could still serve its cached allow"
    );
    eprintln!(
        "TEST7 branch={}",
        if after_release {
            "acked"
        } else {
            "lease-lapsed"
        }
    );
    // And what B does, not only what it holds: the next request is refused.
    refused(&h, &client, &v, NOTES, "gateway A").await;
    assert!(!on_b(&v).await, "gateway B served the revoked session");

    // B never acks: the revoke is waited out to B's lease, and B is no longer
    // caching when it returns. A revoke that returned without waiting would
    // find B's lease still live here.
    let w = visitor(&pool, "w@example.com", true).await;
    assert!(on_b(&w).await && on_b(&w).await);
    proxy.hold_acks().await;
    let started = std::time::Instant::now();
    sign_out(&client, &w).await;
    assert!(
        started.elapsed() <= shared::authz::LEASE * 2,
        "{:?}",
        started.elapsed()
    );
    assert!(!b.is_caching(), "B still caching after the revoke returned");
    assert!(!on_b(&w).await, "gateway B served the revoked session");
    proxy.release();
}

/// Test 8, cached: test 4's shape run twice, so the second round is answered
/// from a warm cache, and still nobody sees anyone else.
#[sqlx::test(migrations = "../../migrations")]
async fn warm_concurrent_visitors_each_see_only_themselves(pool: PgPool) {
    let h = Harness::with_worker(pool.clone()).await;
    let mut visitors = Vec::new();
    for i in 0..64 {
        visitors.push(visitor(&pool, &format!("v{i}@example.com"), true).await);
    }
    let client = h.http();
    use futures::StreamExt as _;
    for round in 0..2 {
        let before = hits(&h);
        let requests = visitors
            .iter()
            .flat_map(|v| std::iter::repeat_n(v, 4))
            .map(|v| {
                let client = client.clone();
                async move { (v, on_notes(&client, "/whoami", &v.cookie, &[]).await) }
            });
        let answers: Vec<_> = futures::stream::iter(requests)
            .buffer_unordered(64)
            .collect()
            .await;
        assert_eq!(answers.len(), 256);
        if answers.iter().any(|(_, (status, _))| *status != 200) {
            support::explain_refusals(&pool).await;
        }
        for (v, (status, json)) in answers {
            assert_eq!(status, 200, "{json}");
            assert_eq!(json["caller"]["subject"], v.subject.as_str(), "{json}");
            assert_eq!(json["caller_after"], json["caller"], "{json}");
        }
        if round == 1 {
            assert_eq!(hits(&h) - before, 256, "the warm round was not all hits");
        }
    }
}

/// A revocation made outside the API, straight in SQL, takes effect within
/// the lease: the contract's 3-second bound for changes no caller waits on.
/// Measured from the commit to the first refused request.
#[sqlx::test(migrations = "../../migrations")]
async fn a_sql_revocation_takes_effect_within_the_lease(pool: PgPool) {
    let h = Harness::with_worker(pool.clone()).await;
    let v = visitor(&pool, "v@example.com", true).await;
    let client = h.http();
    warm(&h, &client, &v, NOTES).await;
    sqlx::query("update sessions set revoked_at = now() where id = $1")
        .bind(v.parent.as_uuid())
        .execute(&pool)
        .await
        .expect("revoke");
    let committed = std::time::Instant::now();
    loop {
        let (status, _) = on_notes(&client, "/whoami", &v.cookie, &[]).await;
        if status != 200 {
            break;
        }
        assert!(
            committed.elapsed() <= shared::authz::LEASE,
            "still served {:?} after the revocation committed",
            committed.elapsed()
        );
    }
    eprintln!("SQLREVOKE took effect after {:?}", committed.elapsed());
}
