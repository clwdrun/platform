# MVP exit criteria

The MVP is done when both demos below pass, end to end, against the deployed
platform. They are the acceptance criteria for the
[MVP — deploy, identity, share](https://github.com/clwdrun/platform/milestone/7)
milestone. An issue belongs in that milestone if a step here cannot pass without it.

Each step names the issues that deliver it. ✅ means closed; ⬜ means still open.
Update the marks as issues close; when every mark in a demo is ✅, run the demo.

## Demo A — a human shares an app

The owner deploys a template app, shares it with a colleague in a **different
org**, and revokes it. Nobody writes authentication code.

| # | Step | Delivered by |
|---|---|---|
| A1 | The owner scaffolds an app from a template (`clwd init`). | ⬜ clwdrun/clwd#29 |
| A2 | The owner runs `clwd deploy`: it builds the app, creates it in their org if it is missing, and publishes it. | ⬜ clwdrun/clwd#88, ⬜ clwdrun/clwd#75, ⬜ #108, ✅ clwdrun/clwd#26, ✅ #6, ✅ #7, ✅ #4 |
| A3 | `clwd deploy` prints the app's URL. | ⬜ clwdrun/clwd#88, ⬜ #108 |
| A4 | The app runs on the platform. | ⬜ #84, ✅ #11 |
| A5 | It answers at `notes.<org>.<apps-domain>`, over TLS, on the real apps domain. | ⬜ #18, ⬜ #5, ⬜ #57, ⬜ #95, ⬜ #97, ⬜ #73 |
| A6 | The owner shares it with a colleague in another org. | ⬜ #14, ⬜ #15, ⬜ #16 |
| A7 | The colleague clicks the link and signs in. | ✅ #9, ✅ #10, ✅ #62, ⬜ #63 |
| A8 | The app shows the colleague's verified identity; the app contains no auth code. | ✅ #11, ✅ #12 |
| A9 | The owner revokes the share; the colleague is refused on their next request. | ⬜ #17, ✅ #12 |

A failure along the way gives the visitor the gateway's own answer, never the
runtime's text, and tells them whether retrying will help (✅ #103).

## Demo B — an agent ships an app

An agent is given **only** the public documentation and an API token. In one
session, with no human steps and no clarifying questions, it writes an app,
deploys it, shares it with a named person, and reports the URL.

**Passes on at least 8 of 10 cold runs.** A cold run is a new session with no
memory of earlier runs.

| # | Step | Delivered by |
|---|---|---|
| B1 | The documentation it reads is public, and it holds an API token. | ⬜ clwdrun/clwd#81, ✅ #3, ✅ #4 |
| B2 | It writes an app from a template. | ⬜ clwdrun/clwd#29 |
| B3 | It runs `clwd deploy` with the token alone — no browser, no cookie — which creates the app if missing and publishes it. | ⬜ clwdrun/clwd#88, ⬜ clwdrun/clwd#75, ⬜ #108, ✅ clwdrun/clwd#26, ✅ #7 |
| B4 | It can find an existing app's id without creating it. | ⬜ #111 |
| B5 | The app serves at its URL. | ⬜ #84, ⬜ #18, ⬜ #5, ⬜ #73 |
| B6 | It shares the app with a named person, using the token. | ⬜ #15, ⬜ #16 |
| B7 | It reports the URL, and the named person can open it. | ⬜ #18, ✅ #11 |
| B8 | 8 of 10 cold runs pass, as scored by the harness. | ⬜ #112 |

## Notes

- **App URLs never move.** An app's URL is built from its `host_label`, which is
  set at creation, never changes, and is never reused, even after the app is
  deleted (#108). Renaming the app changes its display name only, so a link
  shared in step A6 can never come to open a different app.
- **B4 is not on the critical path.** `clwd deploy` already returns the id of
  an app that exists. #111 lets an agent look an id up without the side effect.
