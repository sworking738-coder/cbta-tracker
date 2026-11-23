-- Assessment upgrading forms (PQR, Mechanic, Engineer Madya, Engineer Senior) and personal signatures.

-- 1) Each user's own signature. Only the owner can see or change it.
create table if not exists public.signatures (
  user_id uuid primary key references auth.users(id) on delete cascade default auth.uid(),
  img text not null check (img like 'data:image/%' and length(img) < 300000),
  updated_at timestamptz not null default now()
);
alter table public.signatures enable row level security;
drop policy if exists "own signature" on public.signatures;
create policy "own signature" on public.signatures for all to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

-- 2) Filled forms.
create table if not exists public.assessment_forms (
  id uuid primary key default gen_random_uuid(),
  trainee_id uuid not null references public.trainees(id) on delete cascade,
  kind text not null check (kind in ('pqr','mechanic','madya','senior')),
  data jsonb not null default '{}'::jsonb,
  sigs jsonb not null default '{}'::jsonb,
  created_by uuid default auth.uid() references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default now()
);
create index if not exists assessment_forms_trainee_idx on public.assessment_forms (trainee_id);
alter table public.assessment_forms enable row level security;

drop policy if exists "staff or own mechanic reads forms" on public.assessment_forms;
create policy "staff or own mechanic reads forms" on public.assessment_forms for select to authenticated
  using (public.my_role() in ('assessor','pembina','admin') or trainee_id = public.my_trainee());
drop policy if exists "staff creates forms" on public.assessment_forms;
create policy "staff creates forms" on public.assessment_forms for insert to authenticated
  with check (public.my_role() in ('assessor','pembina','admin'));
drop policy if exists "staff or own mechanic updates forms" on public.assessment_forms;
create policy "staff or own mechanic updates forms" on public.assessment_forms for update to authenticated
  using (public.my_role() in ('assessor','pembina','admin') or trainee_id = public.my_trainee())
  with check (public.my_role() in ('assessor','pembina','admin') or trainee_id = public.my_trainee());
drop policy if exists "admin deletes forms" on public.assessment_forms;
create policy "admin deletes forms" on public.assessment_forms for delete to authenticated
  using (public.my_role() = 'admin');

-- 3) Guard: mechanics change only their personal data and the Applicant signature;
--    every signature is stamped on the server from the signer's own saved signature.
create or replace function public.guard_form() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
  me uuid := auth.uid(); r text := public.my_role(); k text; ov jsonb; nv jsonb;
  personal text[] := case new.kind when 'pqr' then array['G5','G6','G7','G8','G9','G10'] else array['E7'] end;
  img text; nm text;
begin
  if tg_op = 'INSERT' then
    new.created_by := me; new.sigs := '{}'::jsonb;
  else
    new.trainee_id := old.trainee_id; new.kind := old.kind;
    new.created_by := old.created_by; new.created_at := old.created_at;
  end if;
  if tg_op = 'UPDATE' and r = 'mekanik' and (new.data - personal) is distinct from (old.data - personal) then
    raise exception 'Mekanik hanya dapat mengisi data pribadi';
  end if;
  if tg_op = 'UPDATE' then
    for k in select jsonb_object_keys(old.sigs) union select jsonb_object_keys(new.sigs) loop
      ov := old.sigs -> k; nv := new.sigs -> k;
      if ov is not distinct from nv then continue; end if;
      if nv is null or nv = 'null'::jsonb then
        -- clearing a signature: only the signer or admin
        if r <> 'admin' and coalesce(ov->>'uid','') <> me::text then
          raise exception 'Tanda tangan orang lain tidak dapat dihapus';
        end if;
        new.sigs := new.sigs - k;
        continue;
      end if;
      if ov is not null and r <> 'admin' and coalesce(ov->>'uid','') <> me::text then
        raise exception 'Kolom tanda tangan ini sudah diisi orang lain';
      end if;
      if (nv->>'uid') is distinct from me::text then
        raise exception 'Hanya bisa menandatangani atas nama sendiri';
      end if;
      if k = 'applicant' then
        if new.trainee_id is distinct from public.my_trainee() then
          raise exception 'Kolom Applicant hanya untuk mekanik yang bersangkutan';
        end if;
      elsif r not in ('assessor','pembina','admin') then
        raise exception 'Kolom ini hanya untuk assessor / pembina';
      end if;
      select s.img into img from public.signatures s where s.user_id = me;
      if img is null then raise exception 'Buat tanda tangan dulu di Pengaturan'; end if;
      select coalesce(nullif(p.full_name,''), p.email) into nm from public.profiles p where p.id = me;
      new.sigs := jsonb_set(new.sigs, array[k], jsonb_build_object(
        'uid', me, 'name', nm, 'role', r,
        'title', left(coalesce(nv->>'title',''), 60),
        'img', img, 'at', now()));
    end loop;
  end if;
  new.updated_by := me; new.updated_at := now();
  return new;
end $$;
revoke all on function public.guard_form() from public, anon, authenticated;
drop trigger if exists assessment_forms_guard on public.assessment_forms;
create trigger assessment_forms_guard before insert or update on public.assessment_forms
  for each row execute function public.guard_form();

do $$ begin
  alter publication supabase_realtime add table public.assessment_forms;
exception when duplicate_object then null; end $$;

-- 4) Admin edits to the printed template texts and weights, per form kind.
insert into public.app_settings (key, value) values ('form_overrides', '{}'::jsonb)
on conflict (key) do nothing;
