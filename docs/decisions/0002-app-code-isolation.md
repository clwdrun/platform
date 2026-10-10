# Where app code runs, and what it is told (#11)

Decided October 2026. #11 is the first time untrusted, agent-written code runs on
the platform. This records where it runs, what reaches it, and the constraints
that follow.

## The decision: a separate worker process — option (b)

App code runs in **`worker`**, a process of its own under a user of its own. The
gateway reaches it over a Unix socket. One request is one connection: spawn,
invoke, stop.

| | (a) wasm inside the gateway | **(b) one worker process (chosen)** | (c) a worker per org |
|---|---|---|---|
| An escape reads TLS private keys | **every org's** | no | no |
| An escape reads the internal credential | **yes** | no | no |
| An escape reads in-flight requests | every org's | every org's | its own org's |
| A host-panic bug takes down | TLS for every org | app serving | one org's apps |
| Cost | none | one process and one hop (~25–80 µs) | a process and an Engine per active org |

(a) is rejected: a wasmtime escape inside the gateway is a platform compromise.
(c) is the follow-up (#76), and (b) is built so that (c) only adds to it: the hop
already carries `org_id`, and choosing a socket per org is the only change.
**Secrets (#22) reach the worker only after (c) lands.**

### What the worker holds

Read access to the artifact store, compiled components, and the requests in
flight. It holds **no** TLS key, no internal credential and no database URL. The
binary refuses to start if any of `CLWD_INTERNAL_SECRET`, `DATABASE_URL`,
`CLWD_CERT_DIR`, `CLWD_COOKIE_KEY` or `CLWD_GOOGLE_CLIENT_SECRET` is in its
environment. A test starts the real binary and checks its `/proc` environment and
open files.

### The hop treats each side as untrusted

- **Mutual peer checks.** The worker accepts only a peer whose `SO_PEERCRED` uid
  is the gateway's. The gateway sends nothing until the socket's peer runs as the
  worker's uid, so a process that wins the socket path receives no identity and
  no request body.
- **Caps before allocation, on whichever side reads.** Head 512 KiB, body
  16 MiB, 128 headers, 64 KiB of header bytes. A compromised worker cannot make
  the gateway allocate more than that.
- **Filtering after the hop, in the gateway.** Platform `Set-Cookie`s and
  hop-by-hop headers are removed there, whatever the worker sent.
- **One connection per request.** One compromised response cannot poison another
  request's stream. Measured cost: about 30–50 µs at p50 over a persistent
  connection.

### Constraints

- **x86-64 only.** GHSA-jhxm-h53p-jm7w (CVE-2026-34971) is a critical aarch64
  Cranelift miscompile that escapes the sandbox. **A move to ARM must re-check
  wasmtime's advisories first.**
- **wasmtime is compiled with only what we use.** Default features are off, so
  there is no async component model, GC, threads, pooling allocator, WASIp1 or
  WASIp3 (clwd v0.0.2). A feature added back reopens the advisory classes that
  come with it.
- **No egress.** The runtime filters egress by host name only, and a name that
  resolves to an internal address is SSRF. Publish refuses a manifest that grants
  egress, and the worker refuses one at spawn (the authoritative check). #75 adds
  address filtering.

## What the app is told

`clwd:identity@0.2.0` `get-caller()` returns `user(principal)` with:

| Field | Guarantee |
|---|---|
| `subject` | **Pairwise per (app, user)**, a random UUIDv4 stored in `app_subjects`. It is stable forever: across deploys, with no key to rotate. It is never the platform user id. |
| `email` | Verified. It is always present for a person, but typed `option`, so apps must handle `none`. |
| `org` | The app's org, of which the visitor is a member (see below). |
| `display-name` | `none`, because no name is stored. |

There are no roles and no groups. 0.1.0's `in-group`, `list-groups` and
`get-role` always answered "none", so authorization built on them failed open,
and they were removed. `authorize` fails closed with `unavailable`.

**Limit, stated as is:** as long as email is exposed, apps that collude can still
link a visitor by email. Pairwise subjects keep the platform user id inside the
platform, and keep unlinkability possible if email is ever withheld.

### How identity travels

1. The gateway's per-request session check, one SQL statement, returns the
   subject, email and org, and whether the visitor is a member of the app's org.
2. The gateway strips every client header that could claim an identity or an
   origin (`x-clwd-*`, `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, `X-Client-IP`,
   `True-Client-IP`, `CF-Connecting-IP`) and every platform cookie, then sends
   the caller as a **typed field of the hop's head**, never as a header.
3. The worker builds an `IdentityCtx` from it, and spawns with it, naming the app
   id. The app id is never looked up from the digest, because apps built from one
   template share a digest.
4. `get-caller` reads the `Store` built for that request alone.

## Who may reach an app before #12

**Members of the app's org**, by a left join in the same per-request statement,
not a second query. A signed-in non-member gets `gateway.not_a_member` and no app
code runs. #12 replaces this rule with its policy. #15/#16 widen it to "a member,
or holds a grant on this app", and must decide which `org` a cross-org guest is
told.
