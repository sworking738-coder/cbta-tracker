-- 1) Admin can delete a user account (assessment records stay; the trainee record stays).
create or replace function public.admin_delete_user(p_user uuid) returns text
language plpgsql security definer set search_path = '' as $$
begin
  if public.my_role() <> 'admin' then return 'forbidden'; end if;
  if p_user = auth.uid() then return 'self'; end if;
  delete from auth.users where id = p_user;
  if not found then return 'notfound'; end if;
  return 'ok';
end $$;
revoke all on function public.admin_delete_user(uuid) from public, anon;
grant execute on function public.admin_delete_user(uuid) to authenticated;

-- 2) Manual references a mechanic used for each task.
create table if not exists public.task_refs (
  id uuid primary key default gen_random_uuid(),
  trainee_id uuid not null references public.trainees(id) on delete cascade,
  task_id text not null check (length(task_id) between 1 and 20),
  ref text not null check (length(trim(ref)) between 1 and 120),
  created_by uuid default auth.uid() references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);
create unique index if not exists task_refs_uniq
  on public.task_refs (trainee_id, task_id, upper(regexp_replace(trim(ref), '\s+', ' ', 'g')));
create index if not exists task_refs_task_idx on public.task_refs (task_id);
alter table public.task_refs enable row level security;
create policy "staff or own mechanic reads refs" on public.task_refs for select to authenticated
  using (public.my_role() in ('assessor','pembina','admin') or trainee_id = public.my_trainee());
create policy "own mechanic or assessor adds refs" on public.task_refs for insert to authenticated
  with check (trainee_id = public.my_trainee() or public.my_role() in ('assessor','admin'));
create policy "own mechanic or assessor removes refs" on public.task_refs for delete to authenticated
  using (trainee_id = public.my_trainee() or public.my_role() in ('assessor','admin'));
alter publication supabase_realtime add table public.task_refs;

-- 3) Progress milestones (admin can change them in Settings).
insert into public.app_settings (key, value) values
  ('milestones', '[{"pct":85,"label":"Dapat diajukan rating"},{"pct":95,"label":"Dapat diajukan test AMEL"}]'::jsonb)
on conflict (key) do nothing;
