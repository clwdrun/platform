//! Says who is calling and what it was sent, so a test can assert on what the
//! app saw rather than on what the gateway meant to send.
//!
//! - `/` — `hello <email>`: the MVP exit, with no auth code in the app.
//! - anything else — JSON: the caller, the caller read again after a busy
//!   loop (a shared, last-writer-wins caller would show up as a mismatch), and
//!   every header the app received.

use clwd_sdk::http::{RawRequest, ResponseOutparam};
use clwd_sdk::{Caller, Request, Response, caller};

struct App;

impl clwd_sdk::exports::wasi::http::incoming_handler::Guest for App {
    fn handle(raw: RawRequest, out: ResponseOutparam) {
        let headers = raw.headers().entries();
        let request = Request::new(raw);

        let who = caller();
        if request.path() == "/" {
            let body = match &who {
                Caller::User(u) => format!("hello {}", u.email.as_deref().unwrap_or("")),
                _ => "hello".to_owned(),
            };
            Response::ok()
                .header("content-type", b"text/plain")
                .send(out, body.as_bytes());
            return;
        }

        let mut n: u64 = 0;
        for i in 0..200_000u64 {
            n = n.wrapping_add(i);
        }
        std::hint::black_box(n);
        let again = caller();

        let mut json = String::from("{");
        json.push_str(&format!("\"caller\":{},", describe(&who)));
        json.push_str(&format!("\"caller_after\":{},", describe(&again)));
        json.push_str("\"headers\":[");
        for (i, (name, value)) in headers.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!(
                "[{},{}]",
                quote(name),
                quote(&String::from_utf8_lossy(value))
            ));
        }
        json.push_str("]}");
        Response::ok()
            .header("content-type", b"application/json")
            .send(out, json.as_bytes());
    }
}

fn describe(who: &Caller) -> String {
    match who {
        Caller::Anonymous => "null".to_owned(),
        Caller::User(u) => format!(
            "{{\"subject\":{},\"email\":{},\"org\":{}}}",
            quote(&u.subject),
            u.email.as_deref().map_or("null".to_owned(), quote),
            quote(&u.org)
        ),
        Caller::Service(s) => format!("{{\"service\":{}}}", quote(&s.subject)),
    }
}

fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

clwd_sdk::export!(App with_types_in clwd_sdk);
