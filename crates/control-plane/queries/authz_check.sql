-- The per-request decision's one statement (#11, #12): who a live app-host
-- session belongs to, for this app, and the facts the policy decides from.
--
-- Every relation read here is a decision input, and must be in
-- `control_plane::authz::INPUTS` with its invalidation triggers: a test reads
-- this file's plan and fails on any relation that is not, except `authz_seq`.
-- That one is read for `as_of`: the invalidation counter in this statement's
-- own snapshot. Every change numbered at or below it is reflected in this
-- answer, and none above it, so a gateway drops the answer exactly when a
-- later change names one of its tags. The tag columns
-- name what the gateway's cached decision depends on; `ttl_ms` is the
-- remaining life of the earlier-expiring of the two sessions, computed on the
-- database's clock so the gateway never compares its clock with ours.
select sub.subject as "subject: AppSubject",
       u.email,
       ap.org_id as "org_id: OrgId",
       -- #14 replaces: the interim org-member rule's one fact.
       (m.user_id is not null) as "member!",
       a.id as "app_session_id: AppSessionId",
       s.id as "session_id: SessionId",
       u.id as "user_id: UserId",
       greatest(0, extract(epoch from least(a.expires_at, s.expires_at) - now()) * 1000)::bigint
           as "ttl_ms!",
       -- MUST stay a column of this one statement. One statement is one
       -- snapshot, so this number and the decision describe the same moment.
       -- Read in a second query, a revocation committing between the two
       -- would be counted in `as_of` but missing from the decision: the
       -- gateway would see nothing newer than the entry and serve the stale
       -- allow. A test holds this (the_sequence_is_read_in_the_decisions_snapshot).
       (select n from authz_seq) as "as_of!"
  from app_sessions a
  join sessions s       on s.id = a.parent_session_id
  join users u          on u.id = s.user_id
  join apps ap          on ap.id = a.app_id
  join orgs o           on o.id = ap.org_id
  join app_subjects sub on sub.app_id = a.app_id and sub.user_id = u.id
  left join org_members m on m.org_id = ap.org_id and m.user_id = u.id
 where a.secret_sha256 = $1
   and a.app_id = $2
   and a.expires_at > now()
   and s.revoked_at is null
   and s.expires_at > now()
   and u.deleted_at is null
   and ap.deleted_at is null
   and o.deleted_at is null
