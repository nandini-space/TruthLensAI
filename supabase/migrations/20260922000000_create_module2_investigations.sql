-- Apply through the project's Supabase SQL editor or migration workflow.
-- One JSONB snapshot keeps Module 2 artifacts in their existing contract shape.
create table if not exists public.module2_investigations (
    id uuid primary key default gen_random_uuid(),
    scan_id uuid not null unique,
    incident_id uuid unique,
    collected_at timestamptz not null,
    payload jsonb not null,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now())
);
