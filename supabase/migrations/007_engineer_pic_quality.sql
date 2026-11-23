-- New positions: Engineer (same limits as a mechanic, but no CBTA Fundamental),
-- PIC and Quality (same rights as an assessor).

alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check
  check (role in ('pending','mekanik','engineer','assessor','pic','quality','pembina','admin','rejected'));
alter table public.profiles drop constraint if exists profiles_requested_role_check;
alter table public.profiles add constraint profiles_requested_role_check
  check (requested_role in ('mekanik','engineer','assessor','pic','quality','pembina'));

-- Each trainee record is a mechanic (runs CBTA Fundamental) or an engineer (assessment forms only).
alter table public.trainees add column if not exists position text not null default 'mekanik';
alter table public.trainees drop constraint if exists trainees_position_check;
alter table public.trainees add constraint trainees_position_check check (position in ('mekanik','engineer'));

-- Every access rule checks my_role(): PIC/Quality act as assessor, Engineer acts as mechanic.
create or replace function public.my_role() returns text
language sql stable security definer set search_path = '' as $$
  select coalesce((select case role when 'pic' then 'assessor' when 'quality' then 'assessor'
                                    when 'engineer' then 'mekanik' else role end
                   from public.profiles where id = auth.uid()), 'none')
$$;

create or replace function public.my_trainee() returns uuid
language sql stable security definer set search_path = '' as $$
  select trainee_id from public.profiles where id = auth.uid() and role in ('mekanik','engineer')
$$;

-- Staff can see PIC and Quality accounts like other staff.
drop policy if exists "read own, staff read staff, admin all" on public.profiles;
create policy "read own, staff read staff, admin all" on public.profiles for select to authenticated
  using (id = (select auth.uid()) or public.my_role() = 'admin'
         or (public.my_role() in ('assessor','pembina') and role in ('assessor','pic','quality','pembina','admin')));

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
declare m jsonb := coalesce(new.raw_user_meta_data, '{}'::jsonb); rr text; first_admin boolean;
begin
  rr := coalesce(m->>'requested_role', 'mekanik');
  if rr not in ('mekanik','engineer','assessor','pic','quality','pembina') then rr := 'mekanik'; end if;
  first_admin := not exists (select 1 from public.profiles where role = 'admin');
  insert into public.profiles (id, full_name, email, requested_role, emp_no, phone, unit, auth_no, role, approved_at)
  values (new.id, left(coalesce(m->>'full_name', ''), 120), coalesce(new.email, ''), rr,
          left(trim(coalesce(m->>'emp_no', '')), 40), left(coalesce(m->>'phone', ''), 40),
          left(coalesce(m->>'unit', ''), 120), left(coalesce(m->>'auth_no', ''), 60),
          case when first_admin then 'admin' else 'pending' end,
          case when first_admin then now() else null end);
  return new;
end $$;

-- Mechanics and engineers cannot change their own employee number.
create or replace function public.guard_profile_update() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if public.my_role() <> 'admin' then
    new.role := old.role; new.requested_role := old.requested_role; new.trainee_id := old.trainee_id;
    new.approved_at := old.approved_at; new.email := old.email;
    if old.role in ('mekanik','engineer') then new.emp_no := old.emp_no; end if;
  end if;
  return new;
end $$;

-- Approving a mechanic or engineer links (or creates) their trainee record with the right position.
create or replace function public.approve_user(p_user uuid, p_role text) returns text
language plpgsql security definer set search_path = '' as $$
declare p public.profiles; t uuid;
begin
  if public.my_role() <> 'admin' then return 'forbidden'; end if;
  if p_role not in ('mekanik','engineer','assessor','pic','quality','pembina','admin','rejected','pending') then return 'invalid'; end if;
  select * into p from public.profiles where id = p_user;
  if not found then return 'notfound'; end if;
  if p_user = auth.uid() and p_role <> 'admin' then return 'self'; end if;
  if p_role in ('mekanik','engineer') then
    if length(trim(p.emp_no)) = 0 then return 'no_emp'; end if;
    select id into t from public.trainees where lower(trim(emp_no)) = lower(trim(p.emp_no));
    if t is null then
      insert into public.trainees (name, emp_no, location, unit, position, self_registered, created_by)
      values (coalesce(nullif(p.full_name,''), p.emp_no), trim(p.emp_no), p.unit, p.unit, p_role, true, null) returning id into t;
    else
      update public.trainees set position = p_role,
        unit = case when unit = '' and p.unit <> '' then p.unit else unit end
      where id = t;
    end if;
    if exists (select 1 from public.profiles where trainee_id = t and id <> p_user and role in ('mekanik','engineer')) then return 'taken'; end if;
  end if;
  update public.profiles set role = p_role,
    trainee_id = case when p_role in ('mekanik','engineer') then t else null end,
    approved_at = case when p_role in ('pending','rejected') then null else now() end
  where id = p_user;
  return 'ok';
end $$;
revoke all on function public.approve_user(uuid, text) from public, anon;
grant execute on function public.approve_user(uuid, text) to authenticated;
