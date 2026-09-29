alter table public.notes enable row level security;
create policy "owner reads own notes" on public.notes
  for select to authenticated using (owner = auth.uid());
