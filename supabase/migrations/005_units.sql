-- Units (LINE 1-27 and EAM fleets). Admin edits the list in Settings.
insert into public.app_settings (key, value) values ('units', (
  select jsonb_agg(u order by n) from (
    select n, 'LINE ' || n as u from generate_series(1, 27) n
    union all select 101, 'EAM Boeing Fleet'
    union all select 102, 'EAM ATR Fleet'
    union all select 103, 'EAM Airbus Fleet') s))
on conflict (key) do nothing;

-- Each trainee belongs to a unit (separate from the free-text location).
alter table public.trainees add column if not exists unit text not null default '';
create index if not exists trainees_unit_idx on public.trainees (unit);

-- Tidy existing values to the list spelling (e.g. "Line 7" -> "LINE 7").
update public.profiles p set unit = u.v
  from (select jsonb_array_elements_text(value) v from public.app_settings where key = 'units') u
  where lower(regexp_replace(trim(p.unit), '\s+', ' ', 'g')) = lower(u.v) and p.unit <> u.v;
-- A linked mechanic's trainee record takes the unit from the mechanic's profile.
update public.trainees t set unit = p.unit
  from public.profiles p
  where p.trainee_id = t.id and p.role = 'mekanik' and p.unit <> '' and t.unit = '';

-- The sign-up page needs the unit list before anyone is signed in.
drop policy if exists "anyone reads branding" on public.app_settings;
create policy "anyone reads public settings" on public.app_settings for select to anon
  using (key in ('brand_icon', 'brand_bg', 'units'));

-- Approving a mechanic also gives the trainee record the mechanic's unit when it has none yet.
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
      insert into public.trainees (name, emp_no, location, unit, self_registered, created_by)
      values (coalesce(nullif(p.full_name,''), p.emp_no), trim(p.emp_no), p.unit, p.unit, true, null) returning id into t;
    else
      update public.trainees set unit = p.unit where id = t and unit = '' and p.unit <> '';
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
