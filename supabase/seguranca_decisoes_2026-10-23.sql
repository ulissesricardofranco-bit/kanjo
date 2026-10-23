-- =====================================================================================
-- KANJŌ · decisões do Ulisses sobre a auditoria de 23/10/2026
-- Projeto: JAPAO (ref hzlpicbocgsdfuifanqs). Confira no topo do SQL Editor.
-- Independe do seguranca_2026-10-23.sql (pode rodar antes ou depois dele).
--
-- ORDEM: qualquer uma. Testado: o upsert do HTML velho continua lançando pagamento novo do
--   Samuel; o login do HTML velho cai em usuario@kanjo.local quando a RPC some. O HTML novo
--   tira do Samuel os botões de editar/excluir pagamento e não chama mais a RPC.
-- Idempotente.
--
-- Decisões (23/10, pela Central):
--   · comissão do Samuel: "SAMUEL PODE MUDAR" → nada aqui (2.A do correcao_seguranca.sql
--     fica descartado);
--   · pagamentos: "SAMUEL NÃO EDITA PAGAMENTOS" → ele só lança e vê;
--   · esqueci minha senha: "SIM" → fecha a descoberta do e-mail por username;
--   · bucket GAKKIJAPAO: "SIM" → apagar pelo painel (Storage), não por SQL (ver fim);
--   · jogo quarteto no mesmo projeto: "MANTÉM POR ENQUANTO" → nada aqui.
-- =====================================================================================

begin;

-- -------------------------------------------------------------------------------------
-- 1. Pagamentos: o vendedor lança e lê; editar e excluir passam a ser só do comprador.
--    Antes era uma policy ALL para comprador+vendedor: o Samuel podia reduzir ou apagar um
--    pagamento do Ulisses, e o saldo devido a ele subia.
-- -------------------------------------------------------------------------------------
drop policy if exists pagamentos_all    on public.pagamentos;
drop policy if exists pagamentos_select on public.pagamentos;
drop policy if exists pagamentos_insert on public.pagamentos;
drop policy if exists pagamentos_update on public.pagamentos;
drop policy if exists pagamentos_delete on public.pagamentos;

create policy pagamentos_select on public.pagamentos for select to authenticated
  using ((auth.jwt() -> 'app_metadata' ->> 'role') = any (array['comprador','vendedor']));
create policy pagamentos_insert on public.pagamentos for insert to authenticated
  with check ((auth.jwt() -> 'app_metadata' ->> 'role') = any (array['comprador','vendedor']));
create policy pagamentos_update on public.pagamentos for update to authenticated
  using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'comprador')
  with check ((auth.jwt() -> 'app_metadata' ->> 'role') = 'comprador');
create policy pagamentos_delete on public.pagamentos for delete to authenticated
  using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'comprador');

-- -------------------------------------------------------------------------------------
-- 2. "Esqueci minha senha": ninguém de fora descobre mais o e-mail pelo username.
--    Fecha o 2.C do correcao_seguranca.sql pela opção (c). Sai do anon e também do
--    authenticated: logado, o Diego descobriria o e-mail do Samuel. O HTML novo não chama
--    mais a função. Ela continua existindo para o painel/service_role.
--    EFEITO NO DIA A DIA: quem tem e-mail real como login (hoje o Samuel) passa a entrar e a
--    pedir "esqueci minha senha" digitando o e-mail completo. Ulisses e Diego seguem
--    entrando com o usuário curto.
-- -------------------------------------------------------------------------------------
revoke execute on function public.email_por_username(text) from public, anon, authenticated;

commit;

-- =====================================================================================
-- CONFERÊNCIA (só leitura)
-- (a) esperado: pagamentos_select, pagamentos_insert (comprador+vendedor),
--     pagamentos_update e pagamentos_delete (só comprador); nenhuma pagamentos_all
-- select policyname, cmd, qual, with_check from pg_policies
--  where schemaname='public' and tablename='pagamentos' order by 1;
-- (b) esperado: false, false
-- select has_function_privilege('anon','public.email_por_username(text)','execute'),
--        has_function_privilege('authenticated','public.email_por_username(text)','execute');
--
-- BUCKET GAKKIJAPAO (decisão "SIM, pode apagar"): o Supabase não deixa apagar Storage por
-- SQL. No painel do JAPAO: Storage → GAKKIJAPAO → apagar o arquivo sistema-instrumentos.html
-- e depois o bucket. Só existe esse arquivo (cópia velha de 19/08).
--
-- PARA DESFAZER o item 1:
-- drop policy if exists pagamentos_select on public.pagamentos;
-- drop policy if exists pagamentos_insert on public.pagamentos;
-- drop policy if exists pagamentos_update on public.pagamentos;
-- drop policy if exists pagamentos_delete on public.pagamentos;
-- create policy pagamentos_all on public.pagamentos for all to authenticated
--   using ((auth.jwt()->'app_metadata'->>'role') = any (array['comprador','vendedor']))
--   with check ((auth.jwt()->'app_metadata'->>'role') = any (array['comprador','vendedor']));
-- E do item 2: grant execute on function public.email_por_username(text) to anon, authenticated;
-- =====================================================================================
