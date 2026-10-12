-- Gateway leases (#12): which gateways may currently serve cached decisions,
-- and how far through the invalidation stream each has applied.
--
-- A gateway serves from its cache only while it holds a lease. Each ack the
-- relay accepts renews it to `now() + 3 s` on the database's clock (the
-- gateway counts its own copy from when it sent the ack, so it lapses first).
-- A revoke returns once every gateway has either applied the revocation's
-- sequence number or let its lease lapse; a hung or partitioned gateway stops
-- renewing and so stops caching within the lease. In the table, not in a
-- relay's memory, so any control-plane instance can answer that question.
--
-- Deliberately NOT a decision input: no `authz_*` trigger may ever be put on
-- this table. A lease write is a heartbeat, and a heartbeat that invalidated
-- would flush every gateway's cache once a second. A test holds the outbox
-- unchanged across acks.
--
-- Write rate: one upsert per gateway per heartbeat (1 s) plus one per relayed
-- event. Rows idle for an hour are pruned by the relay.
--
-- ROLLBACK PLAN: none required. This migration only creates a table.

create table gateway_leases (
    gateway_id  uuid        primary key,
    applied_seq bigint      not null check (applied_seq >= 0),
    lease_until timestamptz not null,
    renewed_at  timestamptz not null default now()
);
create index gateway_leases_lease_until_idx on gateway_leases (lease_until);
