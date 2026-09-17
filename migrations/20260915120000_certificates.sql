-- Per-org certificate lifecycle state for the gateway's per-org wildcard
-- certificates (`*.{slug}.clwd.run`, #5/#18). Issuance and renewal are the
-- control plane's job; the gateway only reads the resulting certificates to
-- serve them. This table holds STATE ONLY — the certificate and its private key
-- live in the secret broker (#22), never here — so the renewal reconciler can
-- select "due for renewal" without ever touching key material.
--
-- ROLLBACK PLAN: `drop table certificates`. This migration only creates; it
-- drops and rewrites nothing. The table holds in-flight ACME order URLs and
-- renewal-schedule state, not the certificates themselves, so dropping it loses
-- only scheduling/resumption state — the reconciler rebuilds `not_after` and the
-- ARI window from the stored certificates and re-orders any interrupted
-- issuance. No irreversible data loss.

create table certificates (
    -- One wildcard certificate per org, so org_id is the key: at most one row
    -- per org. `on delete restrict` matches orgs' own soft-delete discipline —
    -- a certificate row is not silently dropped when an org is removed.
    org_id     uuid        primary key references orgs (id) on delete restrict,
    -- 'pending' while issuing (no servable certificate yet), 'issued' once a
    -- certificate is stored and served, 'failed' when issuance gave up and needs
    -- the reconciler or an operator to look.
    state      text        not null default 'pending'
                           check (state in ('pending', 'issued', 'failed')),
    -- The in-flight ACME order URL. Resuming an order across a crash or retry
    -- (`Account::order(url)`) instead of starting a fresh one is what keeps a
    -- retry during an outage from burning the 50-new-certificates-per-week
    -- bucket. Null when no issuance is in flight.
    order_url  text,
    -- The issued certificate's notAfter, and the ARI-suggested time to renew
    -- after (RFC 9773). The reconciler selects issued rows whose
    -- ari_renewal_after has passed.
    not_after            timestamptz,
    ari_renewal_after    timestamptz,
    -- Renewal observability: a renewal that fails must be visible, not silent. A
    -- certificate that expires because a renewal failed quietly is an outage
    -- with no deploy behind it, so the last attempt and its error are recorded.
    last_renewal_attempt timestamptz,
    last_renewal_error   text,
    created_at timestamptz not null default now()
);

-- The reconciler's hot query: issued certificates due for renewal, soonest
-- first. Partial on state so pending/failed rows do not bloat the index.
create index certificates_due_idx on certificates (ari_renewal_after)
    where state = 'issued';
