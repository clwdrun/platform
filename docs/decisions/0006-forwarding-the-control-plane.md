# Forwarding the control-plane domain (#95)

The gateway is the only process with a public listener. Requests whose host
is the control-plane domain (`CLWD_CONTROL_PLANE_DOMAIN`) are forwarded to the
control plane's public listener; app hosts are served as before; anything
else is `gateway.unknown_host`. There is no apex host: the control plane and
apps are on separate registrable domains (#62), and no setting names a third.

## Where it goes

`CLWD_CONTROL_PLANE_PUBLIC`, required, is the public listener's URL. The
internal and ops listeners are other addresses serving other routers, so a
request on the public host cannot reach an internal route: it gets the public
router's 404. Nothing in the request chooses the destination.

## TLS

The control-plane domain is served the certificate in `CLWD_PLATFORM_CERT`
and `CLWD_PLATFORM_KEY` (#57 issues it; locally, the development CA). Without
them that name fails the handshake, as any non-app host does.

**SNI must match `Host`.** Every request — on an app host or the control
plane's — is refused with `421 gateway.misdirected_request` unless the TLS
server name and the requested host (port dropped, case-insensitive) are the
same name, before it is routed anywhere. A connection opened for one host
cannot carry a request for another: not an app's connection into the control
plane's cookies, and not the reverse.

## What crosses the hop

- The request as sent, less its hop-by-hop headers. **Cookies pass
  unchanged:** on this host `__Host-clwd_session` and the sign-in state are
  the control plane's own. Removing platform cookies is the app hop's job
  (#62), and applying it here breaks sign-in.
- The gateway's request id in `x-request-id`, replacing any the client sent;
  the control plane accepts it (after `RequestId::sanitize`), so both logs and
  the response carry one id.
- **Nothing added.** No `X-Forwarded-*`, no client address: the control plane
  trusts no forwarded header (0004), and supplying one would invite it to.
- The answer, less hop-by-hop headers, `Set-Cookie` included.

## Buffered, with a budget

Both directions are read whole: the gateway's edge is a pingora `ServeHttp`
app, and nothing on the control plane streams (logs follow is a long-poll of
at most 20 s inside its 30 s timeout; the hop waits 35 s so the control
plane's own timeout answers first). Bodies are capped at
`MAX_BUNDLE_BYTES` (16 MiB), the control plane's own limit, and answers at
16 MiB.

A per-body cap does not bound the sum, and **nothing caps connections**:
pingora 0.8 has no downstream connection limit and the gateway sets none. So
request bodies — to apps and to the control plane alike — are counted against
one byte semaphore, `CLWD_GATEWAY_BODY_BUDGET`, default 256 MiB (sixteen
bodies at the cap; typical bodies are tens of kilobytes). A chunk that does
not fit is refused at once, never queued: a waiting upload pins the bytes it
already holds. The refused upload's bytes go back immediately, the rest of its
body is read and discarded (answering mid-upload leaves the client with a
broken pipe instead of the answer), and it gets `503 gateway.busy`,
retryable, `Retry-After: 1`. Out of budget is an answer, never an
out-of-memory kill of the process holding every org's TLS key.

The budget bounds request bodies only. A connection cap, which would also
bound per-connection state, is not here.
