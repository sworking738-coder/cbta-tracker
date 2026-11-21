-- 1) One employee number = one account (rejected requests free the number again).
create unique index if not exists profiles_emp_no_unique
  on public.profiles (lower(trim(emp_no)))
  where trim(emp_no) <> '' and role <> 'rejected';

-- Sign-up form checks availability before creating the account.
create or replace function public.emp_no_available(p_emp_no text) returns boolean
language sql stable security definer set search_path = '' as $$
  select length(trim(coalesce(p_emp_no, ''))) > 0
     and not exists (select 1 from public.profiles
                     where lower(trim(emp_no)) = lower(trim(p_emp_no)) and role <> 'rejected')
$$;
revoke all on function public.emp_no_available(text) from public;
grant execute on function public.emp_no_available(text) to anon, authenticated;

-- 2) Branding (icon + background) is visible on the login page too.
create policy "anyone reads branding" on public.app_settings for select to anon
  using (key in ('brand_icon', 'brand_bg'));
