-- =====================================================================================
-- KANJŌ · correções de segurança do banco
-- Rodar no SQL Editor do projeto JAPAO (ref hzlpicbocgsdfuifanqs, sa-east-1).
-- Confira no topo do SQL Editor que o projeto é o JAPAO antes de apertar Run.
--
-- O arquivo tem DUAS partes:
--   PARTE 1 — aplicar agora, LOGO DEPOIS do push do sistema-instrumentos.html (ver ORDEM
--             DE APLICAÇÃO abaixo — a ordem inversa tira o login do ar).
--   PARTE 2 — NÃO rodar sem decidir antes. Muda quem pode fazer o quê no dia a dia
--             (o Samuel deixa de definir a própria comissão). Leia os comentários.
--
-- ORDEM DE APLICAÇÃO — leia antes, porque a ordem errada tira o login do ar:
--   1) commit + push do HTML primeiro (o GitHub Pages publica sozinho em ~1 min);
--   2) LOGO EM SEGUIDA colar a PARTE 1 aqui no SQL Editor e rodar;
--   3) rodar a conferência 1.6 e ler os quatro resultados;
--   4) pedir a quem estiver com o sistema aberto que recarregue (Ctrl+F5).
--
--   Por que HTML primeiro: o HTML novo tem um fallback de transição — se a RPC ainda não
--   existir, ele volta a ler a tabela, que nesse momento continua aberta. Ou seja, entre o
--   passo 1 e o passo 2 nada quebra, por mais que demore. O contrário não é verdade: se a
--   PARTE 1 rodar antes do push, o HTML que está no ar (o velho) lê a tabela direto, leva 403
--   e quem já confirmou e-mail real não entra por usuário curto até a página nova subir.
--   Pelo mesmo motivo o passo 4 existe: quem ficou com a página velha em cache cai nesse caso.
--   ATENÇÃO: o fallback é ponte, não solução. Enquanto a PARTE 1 não rodar, a tabela segue
--   aberta e nada aqui foi corrigido de fato — não pare no passo 1.
--   Saída de emergência em qualquer cenário: digitar o e-mail completo no campo de usuário
--   da tela de login (o app aceita, e a mensagem de erro do login avisa isso).
--
-- Tudo aqui é idempotente: pode rodar de novo sem quebrar nada.
-- =====================================================================================


-- =====================================================================================
-- PARTE 1 — APLICAR AGORA
-- Problema: `emailDoUsuario()` roda ANTES do login, ou seja, com a chave anônima. Ela fazia
--   select em `usuarios` filtrando por username. Como a página é pública (GitHub Pages) e a
--   chave publishable está no HTML, qualquer visitante conseguia varrer a tabela inteira e
--   colher os e-mails de recuperação de senha do Ulisses, do Samuel e do Diego. Pior: os
--   privilégios padrão do Supabase (`grant all on all tables in schema public to anon,
--   authenticated`) deixavam também a ESCRITA aberta — qualquer um logado podia trocar o
--   e-mail de recuperação de outro e depois pedir "esqueci minha senha" daquela conta.
-- Correção: a tabela deixa de ser acessível pelo cliente, ponto. Leitura e escrita passam a
--   ser DUAS funções SECURITY DEFINER, cada uma fazendo exatamente uma coisa:
--     · email_por_username(username) → resolve UM username por chamada (tela de login);
--     · registrar_meu_email(email)   → grava o e-mail DA PRÓPRIA linha, com o username
--       derivado do JWT, nunca do que o cliente mandar.
-- Limite honesto desta parte (leia a 2.C): a leitura continua respondendo para anônimo. Ela
--   mata a varredura da tabela (todas as linhas, todas as colunas, inclusive usuários novos),
--   mas não impede alguém que já saiba um username de perguntar por ele.
-- =====================================================================================

-- 1.1 LEITURA. SECURITY DEFINER porque ela precisa ler `usuarios` mesmo depois de a tabela
--     ficar fechada para anon/authenticated. `search_path = ''` é obrigatório em SECURITY
--     DEFINER: sem isso alguém com permissão de criar schema pode sequestrar os nomes não
--     qualificados. Por isso todo objeto abaixo está escrito com schema na frente.
--     STABLE + lower(trim(...)) para casar com o que a tela manda (ela já normaliza).
create or replace function public.email_por_username(p_username text)
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select u.email
  from public.usuarios u
  where u.username = lower(trim(p_username))
  limit 1;
$$;

comment on function public.email_por_username(text) is
  'Resolve username -> e-mail de recuperação para a tela de login. Existe para que a tabela '
  'usuarios NÃO precise ficar legível pelo cliente. Responde um username exato por chamada. '
  'Continua respondendo para anônimo — ver item 2.C do correcao_seguranca.sql.';

-- 1.2 Quem pode chamar. Primeiro tira de PUBLIC (o create dá execute a PUBLIC por padrão),
--     depois devolve só para os dois papéis que a aplicação usa. `anon` precisa porque a
--     chamada acontece na tela de login, antes de existir sessão.
revoke all on function public.email_por_username(text) from public;
grant execute on function public.email_por_username(text) to anon, authenticated;

-- 1.3 ESCRITA. O app precisa gravar o e-mail confirmado na tabela — são duas chamadas no HTML
--     (`aposSenhaOk` e `salvarEmail`). Antes ia por `update ... .eq('username', u)` direto do
--     navegador, e o `u` era escolhido pelo cliente: bastava um usuário logado (Samuel, Diego)
--     mandar `username='ulisses'` para sequestrar o e-mail de recuperação do dono do sistema.
--     Aqui o cliente não diz mais de quem é a linha. O username sai do JWT, do mesmo jeito que
--     a tela deriva (posLogin: user_metadata.usuario || email antes do @).
create or replace function public.registrar_meu_email(p_email text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_username text;
begin
  v_username := lower(trim(coalesce(
    auth.jwt() -> 'user_metadata' ->> 'usuario',
    split_part(coalesce(auth.jwt() ->> 'email', ''), '@', 1)
  )));

  -- sem sessão (ou JWT sem nada que identifique a pessoa) não grava nada
  if v_username is null or v_username = '' then
    return false;
  end if;

  if p_email is null or p_email !~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' then
    raise exception 'E-mail invalido.';
  end if;

  update public.usuarios u
     set email = lower(trim(p_email))
   where u.username = v_username;

  -- false = não existe linha com esse username (o app ignora; a chamada é melhor-esforço,
  -- como já era antes). Se acontecer, confira `select username, email from public.usuarios`.
  return found;
end;
$$;

comment on function public.registrar_meu_email(text) is
  'Grava o e-mail de recuperação da PRÓPRIA linha. O username vem do JWT, nunca do cliente — '
  'é isto que impede um usuário logado de trocar o e-mail de recuperação de outro.';

revoke all on function public.registrar_meu_email(text) from public;
grant execute on function public.registrar_meu_email(text) to authenticated;

-- 1.4 Fechar a tabela DE VERDADE. É este bloco que resolve o achado — sem ele as funções acima
--     são só um caminho alternativo, e o antigo continua aberto.
--     Por que `revoke all` e não só `revoke select`: o Supabase concede por padrão
--     `grant all on all tables in schema public to anon, authenticated`. Revogar só o SELECT
--     deixaria INSERT/UPDATE/DELETE de pé — e privilégio de TABELA vale para todas as colunas,
--     então um `grant update (email)` por coluna não restringiria nada por cima dele.
--     PUBLIC entra na lista porque anon e authenticated herdam de PUBLIC: um grant antigo em
--     PUBLIC sobrevive a qualquer revoke feito nominalmente nesses dois papéis.
--     `service_role` e o dono (postgres) não são tocados — o painel do Supabase continua
--     enxergando e editando a tabela normalmente.
--     `revoke all on table` também varre grants por COLUNA (o Postgres revoga a coluna junto
--     quando o mesmo privilégio sai da tabela), então rodar de novo por cima de qualquer
--     tentativa anterior de `grant select (username)`/`grant update (email)` deixa tudo limpo.
revoke all on table public.usuarios from public;
revoke all on table public.usuarios from anon;
revoke all on table public.usuarios from authenticated;

-- 1.5 Cinto além do suspensório: RLS ligada. Com os privilégios zerados em 1.4 o PostgREST já
--     devolve 403 para anon/authenticated independente de policy; a RLS é a rede para o dia em
--     que alguém rodar um script de setup que reconcede `grant all on all tables`.
--     Ligar RLS só pode restringir, nunca ampliar: policies valem dentro do que o GRANT permite.
--     As duas funções acima continuam funcionando — SECURITY DEFINER roda como o dono da tabela,
--     e o dono não é submetido a RLS (não usamos FORCE ROW LEVEL SECURITY).
--     Para desfazer, se algo inesperado depender de leitura direta:
--        alter table public.usuarios disable row level security;
alter table public.usuarios enable row level security;

-- 1.6 CONFERÊNCIA — BLOQUEANTE. Rode os quatro e leia os resultados logo depois de rodar a
--     PARTE 1 — é o passo 3 da ORDEM DE APLICAÇÃO, com o HTML já publicado no passo 1.
--
-- (a) privilégios por coluna. Esperado: NENHUMA linha com grantee anon, authenticated ou
--     PUBLIC. (Sem filtro de grantee de propósito: um grant em PUBLIC não aparece quando se
--     filtra por 'anon'/'authenticated', e é justamente ele que passa despercebido.)
-- select grantee, privilege_type, column_name
--   from information_schema.column_privileges
--  where table_schema='public' and table_name='usuarios'
--  order by grantee, privilege_type, column_name;
--
-- (b) privilégios por tabela — pega o DELETE, que não existe em nível de coluna e por isso
--     NÃO aparece na consulta (a). Mesmo esperado: nada para anon/authenticated/PUBLIC.
-- select grantee, privilege_type
--   from information_schema.table_privileges
--  where table_schema='public' and table_name='usuarios'
--  order by grantee, privilege_type;
--
-- (c) a RPC de leitura responde? Esperado: o e-mail real do ulisses.
--     Se vier NULL e ele já tiver confirmado e-mail, PARE: acerte a linha antes que ele tente
--     entrar — confira `select username, email from public.usuarios order by 1;` — e avise
--     que, enquanto isso, ele entra digitando o e-mail completo no campo de usuário.
--     Enquanto essa linha estiver errada, ele não entra pelo usuário curto.
-- select public.email_por_username('ulisses') as teste_rpc;
--
-- (d) policies que existem em `usuarios`. Esperado agora: pode não haver nenhuma — com 1.4 e
--     1.5 a tabela está fechada de qualquer forma. O que precisa ser ANOTADO é qualquer policy
--     permissiva com roles={public}: ela volta a valer no dia em que alguém reconceder os
--     grants, e aí a leitura reabre sem ninguém perceber.
-- select policyname, cmd, roles, qual, with_check
--   from pg_policies where schemaname='public' and tablename='usuarios';


-- =====================================================================================
-- PARTE 2 — REQUER DECISÃO DO ULISSES ANTES DE APLICAR
-- Nada abaixo foi aplicado. Está aqui como proposta, comentado, para você decidir.
-- =====================================================================================

-- -------------------------------------------------------------------------------------
-- 2.A [DINHEIRO] O vendedor define a própria comissão
--
-- O achado: `compras.com_pct` é o percentual da comissão do Samuel, e o Samuel tem escrita
-- em `compras` (RLS: comprador+vendedor). A tela dele preenche o campo com o padrão do
-- `config`, mas a tela não é a fronteira de segurança — pelo REST, com a mesma sessão, ele
-- manda um upsert em `compras` com `com_pct` que quiser. E `com_pct` entra direto no acerto
-- que ele recebe:
--     comissão ¥        = (preco_y + frete_jp_y) × com_pct/100
--     total fornecedor ¥ = preco_y + frete_jp_y + comissão + frete BR quando pagador='vendedor'
-- Ou seja: quem recebe a comissão é quem decide a alíquota dela. Combinado de 10–15%, sem
-- teto no banco. Uma compra de ¥300.000 a 15% paga ¥45.000; a 40%, ¥120.000.
--
-- O que NÃO resolve: fechar só a coluna com GRANT. Comprador e vendedor logam no mesmo papel
-- de banco (`authenticated`) — o que os separa é o `app_metadata.role` dentro do JWT. Um
-- `revoke update (com_pct)` tiraria a coluna do Ulisses também. Por isso a proposta é trigger.
--
-- Decisões que você precisa tomar ANTES de rodar:
--   (a) O Samuel pode continuar lançando compras? (a proposta mantém que sim)
--   (b) A comissão de uma compra nova passa a ser sempre `config.com_padrao` quando o
--       lançamento é dele — e você ajusta depois se aquele lote foi negociado diferente?
--   (c) Prefere ERRO na cara dele (proposta abaixo) ou correção silenciosa para o padrão?
--       Erro é mais honesto: ninguém acha que salvou um número que o banco descartou.
--
-- Limite do que isto resolve, para não ficar com falsa sensação: ele continua digitando
-- `preco_y` e `frete_jp_y`, que são a BASE da comissão. Travar a alíquota fecha a porta larga,
-- não o conflito de interesse inteiro. O controle que sobra é a trilha em `logs` (triggers
-- `fn_log`) — vale conferir os lançamentos dele de tempos em tempos.
--
-- create or replace function public.fn_compras_trava_com_pct()
-- returns trigger
-- language plpgsql
-- security definer
-- set search_path = ''
-- as $fn$
-- declare
--   v_role    text;
--   v_padrao  numeric;
-- begin
--   v_role := coalesce(auth.jwt() -> 'app_metadata' ->> 'role', '');
--
--   -- comprador manda no percentual, sem restrição
--   if v_role = 'comprador' then
--     return new;
--   end if;
--
--   if tg_op = 'INSERT' then
--     select c.com_padrao into v_padrao from public.config c where c.id = 1;
--     if new.com_pct is distinct from coalesce(v_padrao, 15) then
--       -- (sem sinal de porcentagem no texto de propósito: em RAISE o % é placeholder)
--       raise exception 'Somente o comprador define o percentual de comissao. Use o padrao: %',
--         coalesce(v_padrao, 15);
--     end if;
--   else
--     if new.com_pct is distinct from old.com_pct then
--       raise exception 'Somente o comprador altera o percentual de comissao desta compra.';
--     end if;
--   end if;
--
--   return new;
-- end;
-- $fn$;
--
-- drop trigger if exists trg_compras_trava_com_pct on public.compras;
-- create trigger trg_compras_trava_com_pct
--   before insert or update on public.compras
--   for each row execute function public.fn_compras_trava_com_pct();
--
-- Para desfazer, se atrapalhar a operação:
-- drop trigger if exists trg_compras_trava_com_pct on public.compras;

-- -------------------------------------------------------------------------------------
-- 2.B [REALTIME] Tirar `usuarios` da publicação do Realtime
--
-- O HTML assina tabela por tabela (`compras`, `pagamentos`, `vendas`, `config`) — mas isso é
-- escolha do cliente, e cliente se troca por um console do navegador. Quem decide o que o
-- servidor tem para entregar é a publicação. Se `usuarios` estiver publicada, alguém logado
-- pode reassinar o schema inteiro e voltar a receber as linhas — dentro do que a RLS dele
-- permitir ler, o que com a PARTE 1 aplicada já é bem menos, mas a publicação é o corte limpo.
--
-- Veja primeiro o que está publicado (o `drop` abaixo dá erro se a tabela não estiver na lista):
-- select tablename from pg_publication_tables where pubname = 'supabase_realtime' order by 1;
--
-- CONFIRME nessa lista que `compras`, `pagamentos`, `vendas` e `config` aparecem — são as quatro
-- que o HTML assina no MESMO canal. Se qualquer uma faltar (ou o assinante não tiver leitura
-- nela), o canal inteiro pode cair em CHANNEL_ERROR e a sincronização ao vivo das quatro morre
-- junto. Depois de mexer na publicação, abra o sistema com a sessão do Diego (role consignado,
-- que é a mais restrita e nem lê `config`) e confira no console do navegador que NÃO aparece
-- "realtime off:" — o aviso que o HTML passou a emitir quando o canal não sobe.
--
-- E tire o que não precisa ser transmitido ao vivo:
-- alter publication supabase_realtime drop table public.usuarios;
--
-- ATENÇÃO ao que NÃO tirar:
--   · `config` PRECISA continuar publicada. É ela que carrega a taxa ¥→R$; sem o evento, a
--     sessão aberta do Samuel segue mostrando todo valor em R$ com o câmbio velho até ele
--     apertar Atualizar. O HTML assina `config` justamente por isso.
--   · `logs` é decisão sua: se você usa a aba de auditoria esperando que ela atualize sozinha,
--     deixe publicada. O HTML não assina `logs` (a aba relê no refresh), então tirar da
--     publicação não muda nada hoje.
--   · `usuarios` não tem motivo nenhum para estar lá.

-- -------------------------------------------------------------------------------------
-- 2.C [ABERTO] O e-mail de recuperação continua saindo para o anônimo
--
-- Este item NÃO está resolvido pela PARTE 1, e é importante não guardar a impressão errada.
-- `email_por_username` é SECURITY DEFINER, tem `grant execute ... to anon` e devolve o e-mail
-- em texto puro para quem não está logado. Neste sistema só existem 3 usuários, e os três
-- usernames estão publicados na tabela do CLAUDE.md deste mesmo repositório público. Ou seja:
-- quem quiser os e-mails lê o CLAUDE.md, faz 3 chamadas em /rest/v1/rpc/email_por_username com
-- a chave publishable que está no HTML, e colhe o mesmo que colhia antes. O que a PARTE 1
-- fechou foi a varredura da TABELA (todas as linhas, todas as colunas, inclusive usuários que
-- venham a existir) e, principalmente, a ESCRITA. A consulta dirigida continua de pé. Não há
-- rate limit, captcha nem exigência de sessão.
--
-- As três saídas reais, para você escolher (nenhuma cabe só neste arquivo):
--   (a) Edge Function com service_role: a função resolve username→e-mail internamente e chama
--       a API de recovery do Auth. O e-mail NUNCA volta para o navegador. Aí
--       `email_por_username` perde o `grant execute to anon` e o "esqueci minha senha" passa a
--       ser um POST para a função. É a correção de verdade; exige publicar uma função.
--   (b) Meio-termo: a RPC devolve o e-mail MASCARADO (u***@g***.com) só para feedback de tela,
--       e o disparo do reset vai por Edge Function. Também exige a função.
--   (c) Mais simples e sem função nenhuma: tirar o `grant execute to anon` e aceitar que
--       "esqueci minha senha" e o login de quem tem e-mail real passem a exigir digitar o
--       e-mail completo. Fecha o vazamento hoje, ao custo de o usuário precisar lembrar o
--       e-mail. Se você topar, é só rodar:
--          revoke execute on function public.email_por_username(text) from anon;
--       (o HTML já trata os DOIS fluxos: o campo de usuário aceita e-mail completo, a mensagem
--        de erro do login diz isso, e o "esqueci minha senha" — que também para de resolver o
--        username quando o grant sai — pede o e-mail completo em vez de afirmar que a pessoa
--        não cadastrou e-mail.)


-- =====================================================================================
-- AÇÃO FORA DO BANCO — a senha padrão está queimada
-- A senha padrão de primeiro acesso estava em texto puro dentro do sistema-instrumentos.html
-- (comparação `if(senha==='...')`), num repositório PÚBLICO. Ela foi tirada do arquivo agora,
-- mas continua no histórico do Git já publicado — e reescrever histórico não é uma opção sã
-- num repo que já está no ar. Tratar como comprometida:
--   1) trocar a senha de qualquer usuário que ainda esteja com ela, pelo painel do Supabase
--      (Authentication → Users → ... → Reset/Update password);
--   2) confirmar que os usuários criados de agora em diante nasçam com
--      `user_metadata.trocar = true` (o app força a troca no primeiro acesso);
--   3) não repor a constante no HTML. A checagem "não repita a senha padrão" agora compara com
--      a senha que a pessoa acabou de digitar para entrar, o que dá o mesmo efeito sem
--      publicar segredo nenhum.
-- Enquanto a senha antiga valer para algum usuário, todo o resto deste arquivo é secundário.
-- =====================================================================================


-- =====================================================================================
-- NOTA (fora do banco) — regerar o hash SRI do supabase-js
-- O <script> do HTML agora está preso na versão 2.112.4 com `integrity`. Ao subir de versão,
-- o hash muda e o navegador recusa o arquivo até você trocar os dois juntos. Para gerar:
--
--   curl -s https://cdn.jsdelivr.net/npm/@supabase/supabase-js@<VERSAO>/dist/umd/supabase.js \
--     | openssl dgst -sha384 -binary | openssl base64 -A
--
-- Use sempre o caminho .../dist/umd/supabase.js (arquivo publicado no npm, bytes fixos).
-- NÃO use .../supabase.min.js nem a URL curta sem caminho: ali o jsDelivr gera o arquivo na
-- hora e o próprio jsDelivr avisa, no cabeçalho do arquivo, para não usar SRI com eles.
-- =====================================================================================
