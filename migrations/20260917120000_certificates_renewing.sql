-- The renewal reconciler's claim state (#5 Part 2): `renewing` marks a row a
-- worker has claimed and is driving (or died driving). `issued` with a past
-- `ari_renewal_after` is "due"; `renewing` with an old `last_renewal_attempt`
-- is "stale, reclaim" — a crash between the claim commit and
-- `cert_mark_issued` must not strand the row, so the next pass resumes it via
-- `order_url`; `failed` with an old attempt is "retry with backoff".
--
-- ROLLBACK PLAN: `alter table certificates drop constraint
-- certificates_state_check`, then re-add the three-state check
-- (`check (state in ('pending', 'issued', 'failed'))`), then
-- `drop index certificates_renewing_idx`. Only scheduling/claim state is
-- affected — rows in `renewing` revert to no valid state, so re-mark any such
-- rows `pending` (to resume as fresh orders) or `failed` (for the reconciler's
-- retry arm) before re-adding the old check. No key material lives here.

alter table certificates drop constraint certificates_state_check;
alter table certificates
    add constraint certificates_state_check
    check (state in ('pending', 'issued', 'failed', 'renewing'));

-- The reconciler's reclaim arm: stale `renewing` rows, oldest first. Partial,
-- so issued/pending/failed rows never enter it.
create index certificates_renewing_idx on certificates (last_renewal_attempt)
    where state = 'renewing';
