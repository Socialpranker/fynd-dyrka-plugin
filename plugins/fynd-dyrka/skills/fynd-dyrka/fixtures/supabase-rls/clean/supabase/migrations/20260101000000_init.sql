-- Control group for scan_supabase_migrations: same shapes as ../bad, done right.
-- The traps below must NOT produce findings.

-- Comments are stripped: using (true) here and `security definer` in a comment.
create table public.profiles (
  id uuid primary key references auth.users (id),
  email text not null,
  is_admin boolean not null default false
);
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles
  for select to authenticated using (auth.uid() = id);

-- RLS for this table is enabled in the NEXT migration file (cross-file state).
create table public.notes (
  id bigint generated always as identity primary key,
  owner uuid not null references auth.users (id),
  body text not null
);

-- USING (true) restricted to service_role only: not exposed to anon/authenticated.
create policy "service role full access" on public.notes
  for all to service_role using (true) with check (true);

-- SECURITY DEFINER with a fixed search_path, in the same statement.
create function public.grant_admin(uid uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  update public.profiles set is_admin = true where id = uid;
end;
$$;

-- A plain function whose BODY mentions the phrase: not a definer function.
create function public.describe() returns text language sql as $$
  select 'this is not security definer'::text
$$;

-- security_invoker view.
create view public.profile_emails with (security_invoker = true) as
  select id, email from public.profiles;
