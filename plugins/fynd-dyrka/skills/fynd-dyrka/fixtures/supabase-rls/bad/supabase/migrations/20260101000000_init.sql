-- Deliberately insecure Supabase migration: fixture for scan_supabase_migrations.

-- 1. public table that no migration ever enables RLS on (lint 0013)
create table public.profiles (
  id uuid primary key references auth.users (id),
  email text not null,
  is_admin boolean not null default false
);

create table public.notes (
  id bigint generated always as identity primary key,
  owner uuid not null references auth.users (id),
  body text not null
);
alter table public.notes enable row level security;

-- 2. permissive policies (lint 0024): read-for-everyone and write-for-everyone
create policy "notes are readable by everyone" on public.notes
  for select using (true);
create policy "any signed-in user can change any note" on public.notes
  for all to authenticated using (true) with check (true);

-- 3. authorisation from user_metadata (lint 0015)
create policy "admins update notes" on public.notes
  for update to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

-- 4. SECURITY DEFINER without a fixed search_path (lint 0011)
create function public.grant_admin(uid uuid) returns void
language plpgsql security definer as $$
begin
  update public.profiles set is_admin = true where id = uid;
end;
$$;

-- 5. view without security_invoker (lint 0010)
create view public.profile_emails as select id, email from public.profiles;
