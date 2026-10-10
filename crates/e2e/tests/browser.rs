//! Session isolation, in a real browser (#62).
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
        .open(&format!("https://{CONTROL_PLANE}/healthz"))
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
    let state_cookie = set_cookie_value(&begun, "__Host-clwd_state").expect("state cookie");
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
            format!("__Host-clwd_state={state_cookie}"),
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
        ("state", &state_cookie),
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
