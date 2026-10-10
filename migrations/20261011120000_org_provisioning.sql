-- Org provisioning (#10): how a signed-in person comes to belong to an org.
--
-- Every later authorization decision (#12, #14, #15, #17) hangs off
-- org_members, so the rule for writing a row there is deliberately narrow.
-- Every ambiguous case resolves toward NOT joining: a join can be granted
-- later; an unwanted one cannot be un-seen.
--
-- ROLLBACK PLAN: none required. This migration creates two tables and adds a
-- column each to org_members and users; it drops and rewrites nothing. The
-- org_members column is added NOT NULL with no default, which fails loudly if org_members has rows — it
-- has none anywhere, because the control plane has never served a request
-- (#48), and a row whose origin is unknown must not be given one by guess.
-- Reverting is dropping the two tables and the two columns; the users column
-- is refilled by the next sign-in.

-- ---------------------------------------------------- org_members.joined_via ----

-- How a membership came about. Sign-in sync removes only memberships it would
-- itself have created: 'domain' (auto-joined through a verified domain) and
-- 'claimant' (the person who verified that domain). Without this column, an
-- invited member (#16, which adds 'invite') whose Google hosted domain never
-- matched would be deleted by the "hd no longer matches" rule on their next
-- sign-in. 'personal' is the sole member of a personal org.
--
-- TEXT with a CHECK, like apps.runtime: #16 adds a value by swapping the
-- constraint, inside a transaction.
alter table org_members
    add column joined_via text not null
        check (joined_via in ('personal', 'domain', 'claimant'));

-- At most one personal org per person. The sign-in path also locks the user
-- row, so two concurrent first sign-ins cannot both create one; this makes the
-- invariant the database's rather than the code's.
create unique index org_members_one_personal_org_idx
    on org_members (user_id) where joined_via = 'personal';

-- -------------------------------------------------------- users.hosted_domain ----

-- The Google hosted domain (`hd`) the user last signed in with, normalised;
-- null for a consumer account. Refreshed on every sign-in, so it is at most a
-- session lifetime stale. A domain claim checks it: a person may only claim
-- the domain of the Workspace tenant they are in. Never derived from the email
-- address — a consumer account registered as bob@acme.com has a verified
-- acme.com email and no hosted domain.
alter table users
    add column hosted_domain text
        check (hosted_domain = lower(hosted_domain) and char_length(hosted_domain) <= 253);

-- -------------------------------------------------------------- org_domains ----

-- A domain an org has proven it controls, by DNS. One verified org per domain:
-- the primary key is the uniqueness rule, and the CHECK keeps the key in the
-- one normalised spelling (lowercase, punycode, no trailing dot) so `Acme.com`
-- and `acme.com.` cannot be two verified domains.
--
-- Hard to get, deliberately: there is no path that writes a row here except a
-- DNS-verified claim, and none that moves a verified domain to another org.
create table org_domains (
    domain      text        primary key
                            check (domain = lower(domain)
                                   and char_length(domain) <= 253
                                   and domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    org_id      uuid        not null references orgs (id) on delete restrict,
    -- The user who proved control. Until #14 brings roles, the only person who
    -- may change auto_join; if they leave, an operator does.
    claimant_id uuid        not null references users (id) on delete restrict,
    -- Whether a person whose Google hosted domain is this domain joins the org
    -- on sign-in. Off unless the claimant turned it on: a contractor holding a
    -- temporary account in the tenant would otherwise land in everything the
    -- org can see.
    auto_join   boolean     not null default false,
    verified_at timestamptz not null default now()
);

create index org_domains_org_id_idx on org_domains (org_id);

-- ------------------------------------------------------------ domain_claims ----

-- A claim in progress: the claimant has been given a TXT value to publish and
-- has not yet proven it. Reserves nothing — not the domain (several people may
-- race; the first to verify wins, through org_domains' key) and not the slug
-- (taken only when the org is created at verification). An expired claim is
-- inert: verification refuses it.
--
-- The org does not exist yet, so the token is bound to the claim: this
-- claimant, this domain, this requested slug. Creating the org up front would
-- burn an immutable slug before control of anything was proven.
create table domain_claims (
    id          uuid        primary key,
    domain      text        not null
                            check (domain = lower(domain)
                                   and char_length(domain) <= 253
                                   and domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    claimant_id uuid        not null references users (id) on delete restrict,
    slug        text        not null
                            check (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    auto_join   boolean     not null default false,
    -- The value to publish at _clwd-verify.<domain>. Public by design — it
    -- sits in DNS — so stored as is.
    token       text        not null,
    expires_at  timestamptz not null,
    created_at  timestamptz not null default now()
);

create index domain_claims_claimant_id_idx on domain_claims (claimant_id);
