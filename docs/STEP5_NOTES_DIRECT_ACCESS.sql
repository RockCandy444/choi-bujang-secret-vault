-- 5단계: 학습 DB에서 사용자가 검토 후 직접 실행하는 SQL 제안입니다.
-- 아직 DB에 적용하지 않았습니다. 대상은 기존 public.notes 한 테이블뿐입니다.
-- 메모/소유자/다른 테이블/Auth/RLS/정책/서버 설정은 변경하지 않습니다.
-- 실행 위치: Supabase -> 학습 프로젝트 -> SQL Editor -> New query.
-- 순서: 화면에서 A 정상 CRUD 확인 -> 1만 선택해 Run -> 결과 검토
--       -> 2 전체를 선택해 Run -> 1을 다시 실행 -> A 화면 CRUD 재확인.
-- 기존 A 메모 대신 새 가상 메모를 추가/조회/수정/삭제해 확인하세요.
-- 비밀번호/키/토큰/메모 본문을 SQL이나 결과 공유에 넣지 마세요.

-- 1. 적용 전후 공통 확인 (이 영역만 실행하면 읽기 전용입니다.)
-- PUBLIC은 실제 로그인 역할이 아니므로 ACL에서 확인합니다.
-- 적용 후 PUBLIC/anon/authenticated의 행은 없어야 합니다.
select grantee, privilege_type, is_grantable
from information_schema.table_privileges
where table_schema = 'public' and table_name = 'notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated', 'service_role')
order by grantee, privilege_type;

-- 별도의 열 권한도 확인합니다. 적용 후 세 대상의 행은 없어야 합니다.
select grantee, column_name, privilege_type, is_grantable
from information_schema.column_privileges
where table_schema = 'public' and table_name = 'notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated')
order by grantee, column_name, privilege_type;

-- 상속/PUBLIC을 포함한 실제 유효 권한을 확인합니다.
-- 적용 후 anon/authenticated: 모든 값 false.
-- service_role: can_select/can_insert/can_update/can_delete 모두 true.
select role_name,
  has_table_privilege(role_name, 'public.notes', 'SELECT') as can_select,
  has_table_privilege(role_name, 'public.notes', 'INSERT') as can_insert,
  has_table_privilege(role_name, 'public.notes', 'UPDATE') as can_update,
  has_table_privilege(role_name, 'public.notes', 'DELETE') as can_delete,
  has_table_privilege(role_name, 'public.notes',
    'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER') as any_table_privilege,
  has_any_column_privilege(role_name, 'public.notes',
    'SELECT, INSERT, UPDATE, REFERENCES') as any_column_privilege
from (values ('anon'::text), ('authenticated'::text), ('service_role'::text)) as roles(role_name)
order by role_name;

-- 본문/ID/소유자 값을 출력하지 않습니다. 작업 전후 RLS 설정은 같아야 합니다.
select relrowsecurity as rls_enabled, relforcerowsecurity as rls_forced
from pg_class where oid = 'public.notes'::regclass;
select count(*) as note_count from public.notes;
-- note_count는 A의 확인 메모 삭제까지 마친 시점끼리 비교합니다.
-- 동시 사용자 변경이 없으면 같아야 합니다. 이 SQL에는 자료 변경문이 없습니다.

-- 2. 권한 회수 (BEGIN부터 COMMIT까지 한 번에 선택해 실행합니다.)
-- 오류가 나면 이 트랜잭션은 커밋되지 않습니다. 첫 오류만 확인하세요.
-- SQL Editor 세션에 트랜잭션 오류가 남아 있으면 ROLLBACK;만 실행합니다.
begin;

-- 서버 함수가 이미 사용하는 service_role의 CRUD 권한을 먼저 확인합니다.
-- 권한이 없으면 변경 전에 중단하며 서버 권한을 임의로 바꾸지 않습니다.
do $check_server$
begin
  if not (
    has_schema_privilege('service_role', 'public', 'USAGE')
    and has_table_privilege('service_role', 'public.notes', 'SELECT')
    and has_table_privilege('service_role', 'public.notes', 'INSERT')
    and has_table_privilege('service_role', 'public.notes', 'UPDATE')
    and has_table_privilege('service_role', 'public.notes', 'DELETE')
  ) then
    raise exception 'NOTES_SERVER_CRUD_PRIVILEGES_REQUIRED';
  end if;
end;
$check_server$;

-- public.notes만 지정합니다. 같은 대상의 해당 열 권한/재부여 권한도 회수됩니다.
-- RESTRICT로 다른 수혜자에게 이어진 권한이 있으면 변경 대신 오류로 중단합니다.
revoke all privileges on table public.notes from PUBLIC, anon, authenticated restrict;

-- 다른 역할에서 상속받은 권한 등이 남는 경우 성공으로 처리하지 않습니다.
-- 서버 권한이 PUBLIC 회수의 영향을 받아도 전체 변경을 취소합니다.
do $check_result$
declare
  client_role text;
begin
  foreach client_role in array array['anon', 'authenticated'] loop
    if has_table_privilege(client_role, 'public.notes',
         'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
       or has_any_column_privilege(client_role, 'public.notes',
         'SELECT, INSERT, UPDATE, REFERENCES') then
      raise exception 'NOTES_DIRECT_PRIVILEGES_REMAIN: %', client_role;
    end if;
  end loop;
  if not (
    has_schema_privilege('service_role', 'public', 'USAGE')
    and has_table_privilege('service_role', 'public.notes', 'SELECT')
    and has_table_privilege('service_role', 'public.notes', 'INSERT')
    and has_table_privilege('service_role', 'public.notes', 'UPDATE')
    and has_table_privilege('service_role', 'public.notes', 'DELETE')
  ) then
    raise exception 'NOTES_SERVER_CRUD_PRIVILEGES_LOST';
  end if;
end;
$check_result$;

commit;

-- 3. 적용 후 1을 다시 실행하고, A 로그인 -> 새 가상 메모 추가 -> 수정 -> 삭제.
-- 정상: 앱의 GET/PUT/DELETE 200, POST 201, 로그인/로그아웃 정상.
-- 거부: 앱 무로그인/잘못된 인증 401, 상대 메모 접근 404, 소유자 변경 PUT 400.
-- 원본 /rest/v1/notes의 anon 키 직접 요청은 심판이 확인합니다.
-- 이 파일 실행/로컬 모의 검사/관리자 SELECT는 그 심판 검사를 대신하지 않습니다.
-- SQL 참고: https://www.postgresql.org/docs/current/sql-revoke.html
-- 접근 계층: https://supabase.com/docs/guides/api/securing-your-api
