-- Every role signs up and requests a role; admin approves.
alter table public.profiles drop constraint profiles_role_check;
alter table public.profiles add constraint profiles_role_check check (role in ('pending','mekanik','assessor','pembina','admin','rejected'));
alter table public.profiles
  add column requested_role text not null default 'mekanik' check (requested_role in ('mekanik','assessor','pembina')),
  add column emp_no text not null default '',
  add column phone text not null default '',
  add column unit text not null default '',
  add column auth_no text not null default '',
  add column trainee_id uuid references public.trainees(id) on delete set null,
  add column approved_at timestamptz,
  add column prefs jsonb not null default '{}'::jsonb;

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
declare m jsonb := coalesce(new.raw_user_meta_data, '{}'::jsonb); rr text; first_admin boolean;
begin
  rr := coalesce(m->>'requested_role', 'mekanik');
  if rr not in ('mekanik','assessor','pembina') then rr := 'mekanik'; end if;
  first_admin := not exists (select 1 from public.profiles where role = 'admin');
  insert into public.profiles (id, full_name, email, requested_role, emp_no, phone, unit, auth_no, role, approved_at)
  values (new.id,
          left(coalesce(m->>'full_name', ''), 120),
          coalesce(new.email, ''),
          rr,
          left(trim(coalesce(m->>'emp_no', '')), 40),
          left(coalesce(m->>'phone', ''), 40),
          left(coalesce(m->>'unit', ''), 120),
          left(coalesce(m->>'auth_no', ''), 60),
          case when first_admin then 'admin' else 'pending' end,
          case when first_admin then now() else null end);
  return new;
end $$;
revoke all on function public.handle_new_user() from public, anon, authenticated;

-- Users edit their own contact fields; only admin changes role, link or request.
create or replace function public.guard_profile_update() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if public.my_role() <> 'admin' then
    new.role := old.role; new.requested_role := old.requested_role; new.trainee_id := old.trainee_id;
    new.approved_at := old.approved_at; new.email := old.email;
    if old.role = 'mekanik' then new.emp_no := old.emp_no; end if;
  end if;
  return new;
end $$;
revoke all on function public.guard_profile_update() from public, anon, authenticated;
create trigger profiles_guard before update on public.profiles for each row execute function public.guard_profile_update();

drop policy "admin updates profiles" on public.profiles;
create policy "own or admin updates profile" on public.profiles for update to authenticated
  using (id = (select auth.uid()) or public.my_role() = 'admin')
  with check (id = (select auth.uid()) or public.my_role() = 'admin');
drop policy "read own profile or admin reads all" on public.profiles;
create policy "read own, staff read staff, admin all" on public.profiles for select to authenticated
  using (id = (select auth.uid()) or public.my_role() = 'admin'
         or (public.my_role() in ('assessor','pembina') and role in ('assessor','pembina','admin')));

create or replace function public.my_trainee() returns uuid
language sql stable security definer set search_path = '' as $$
  select trainee_id from public.profiles where id = auth.uid() and role = 'mekanik'
$$;
revoke all on function public.my_trainee() from public, anon;
grant execute on function public.my_trainee() to authenticated;

create policy "mechanic reads own trainee" on public.trainees for select to authenticated
  using (id = public.my_trainee());
create policy "mechanic reads own signoffs" on public.signoffs for select to authenticated
  using (trainee_id = public.my_trainee());

-- Admin approves or rejects a request. Approving a mechanic links (or creates) the trainee record by employee number.
create or replace function public.approve_user(p_user uuid, p_role text) returns text
language plpgsql security definer set search_path = '' as $$
declare p public.profiles; t uuid;
begin
  if public.my_role() <> 'admin' then return 'forbidden'; end if;
  if p_role not in ('mekanik','assessor','pembina','admin','rejected','pending') then return 'invalid'; end if;
  select * into p from public.profiles where id = p_user;
  if not found then return 'notfound'; end if;
  if p_user = auth.uid() and p_role <> 'admin' then return 'self'; end if;
  if p_role = 'mekanik' then
    if length(trim(p.emp_no)) = 0 then return 'no_emp'; end if;
    select id into t from public.trainees where lower(trim(emp_no)) = lower(trim(p.emp_no));
    if t is null then
      insert into public.trainees (name, emp_no, location, self_registered, created_by)
      values (coalesce(nullif(p.full_name,''), p.emp_no), trim(p.emp_no), p.unit, true, null) returning id into t;
    end if;
    if exists (select 1 from public.profiles where trainee_id = t and id <> p_user and role = 'mekanik') then return 'taken'; end if;
  end if;
  update public.profiles set role = p_role,
    trainee_id = case when p_role = 'mekanik' then t else null end,
    approved_at = case when p_role in ('pending','rejected') then null else now() end
  where id = p_user;
  return 'ok';
end $$;
revoke all on function public.approve_user(uuid, text) from public, anon;
grant execute on function public.approve_user(uuid, text) to authenticated;

-- Anonymous ID lookup is replaced by mechanic accounts.
revoke execute on function public.mechanic_progress(text) from anon, authenticated;
revoke execute on function public.register_mechanic(text,text,text,text,date) from anon, authenticated;

-- App-wide settings (admin writes, signed-in users read)
create table public.app_settings (
  key text primary key,
  value jsonb not null,
  updated_at timestamptz not null default now()
);
alter table public.app_settings enable row level security;
create policy "signed-in read settings" on public.app_settings for select to authenticated using (true);
create policy "admin writes settings" on public.app_settings for all to authenticated
  using (public.my_role() = 'admin') with check (public.my_role() = 'admin');
insert into public.app_settings (key, value) values ('stale_days', '30'::jsonb), ('stat_max', '10'::jsonb);

create index profiles_trainee_idx on public.profiles (trainee_id);
