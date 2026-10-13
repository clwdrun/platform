-- An app's host label (#108): its half of `{app}.{org}.<apps domain>`.
--
-- The URL used to be built from `apps.name`, which is mutable. Renaming an app
-- would free its name for another app to claim, and every link ever shared to
-- the first app would then open the second — the reuse hazard the org slug's
-- guard closes for orgs. So the host gets its own column:
--
-- - set once, at creation, and refused any change by the trigger below, which
--   holds against a hand-run UPDATE as well as application code;
-- - unique per org with no `deleted_at` condition, so a deleted app's label is
--   never freed: apps are only soft-deleted, and the foreign keys on its
--   versions and sessions restrict a hard delete;
-- - the same DNS label rule as `apps.name`.
--
-- `name` stays, as the display name. Existing rows take their label from it.
-- Additive only: the previous build never reads `host_label`, and the backfill
-- makes every existing app's label equal the name it is routed by today.

alter table apps add column host_label text;

update apps set host_label = name;

alter table apps
    alter column host_label set not null,
    add constraint apps_host_label_check
        check (host_label ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    add constraint apps_org_id_host_label_key unique (org_id, host_label);

create function apps_host_label_guard() returns trigger language plpgsql as $$
begin
    if new.host_label is distinct from old.host_label then
        raise exception 'app host label is immutable (% -> %)', old.host_label, new.host_label
            using errcode = 'restrict_violation';
    end if;
    return new;
end;
$$;

create trigger apps_host_label_guard
    before update on apps
    for each row execute function apps_host_label_guard();
