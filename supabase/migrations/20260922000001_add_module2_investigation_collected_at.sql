-- Preserve the existing evidence collection time for deterministic history pages.
-- The backfill keeps investigations created before Task 20 listable.
alter table public.module2_investigations
    add column if not exists collected_at timestamptz;

update public.module2_investigations
set collected_at = created_at
where collected_at is null;

alter table public.module2_investigations
    alter column collected_at set not null;
