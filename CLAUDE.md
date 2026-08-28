# KANJŌ — Controle de Instrumentos Japão→Brasil

Sistema de controle de compra, importação e venda de instrumentos musicais. Negócio do Ulisses:
compra em leilões no Japão via intermediário (**Samuel**, o "vendedor", que recebe comissão de
10–15%), paga com depósitos em R$ convertidos a ¥, e revende no Brasil — em parte via **Diego**
(vendedor consignado).

## Arquitetura

- **Single-file**: todo o sistema é `sistema-instrumentos.html` (HTML+CSS+JS, sem build).
  Funciona aberto localmente (`file://`) e publicado no GitHub Pages.
- `index.html` é apenas um **redirect** para `sistema-instrumentos.html` — nunca edite os dois;
  o canônico é sempre `sistema-instrumentos.html`.
- **Backend**: Supabase, projeto `JAPAO` (ref `hzlpicbocgsdfuifanqs`, sa-east-1). Chave
  publishable embutida no HTML (pública, ok). Realtime ligado — a tela recarrega ao vivo.
- **Publicação**: https://ulissesricardofranco-bit.github.io/kanjo/ (GitHub Pages, branch `main`
  deste repo). Para publicar: commit + push. O deploy leva ~1 min.

## Banco (Supabase)

Tabelas: `compras`, `pagamentos`, `vendas`, `config` (id=1: taxa, com_padrao), `usuarios`
(username→email p/ login e recuperação de senha), `logs` (auditoria por triggers `fn_log` em
todas as tabelas — nunca remova os triggers).

Colunas que carregam regra de negócio:
- `compras.frete_br_pagador` ('vendedor'|'comprador') e `compras.itens` (jsonb, lotes).
- `vendas.compra_id` + `vendas.item_id` — vínculo venda↔compra/item. Existe **índice único**
  `vendas_compra_item_uniq (compra_id,item_id) where item_id is not null` que impede vendas
  duplicadas por item (o sync depende dele para ser à prova de corrida).
- `vendas.custo_consignado` (o custo que o Diego vê) e `vendas.custos_extras` (jsonb:
  `[{tipo: frete_entrega|taxa_cartao|reforma|outros, desc, valor}]`).

## Usuários e permissões (RLS)

| Login | Papel (`app_metadata.role`) | Vê |
|---|---|---|
| `ulisses` | `comprador` | tudo |
| `samuel` | `vendedor` | compras, pagamentos, fluxo Japão (sem vendas/lucros) |
| `diego` | `consignado` | só vendas com `custo_consignado` preenchido (aba Consignação) |

Login = usuário curto + sufixo `@kanjo.local` (a tabela `usuarios` resolve e-mail real quando
cadastrado). Senha padrão de novo usuário: `denfa123` com `user_metadata.trocar=true` (o app
força troca). RLS: escrita em vendas/config só comprador; compras/pagamentos só
comprador+vendedor; logs select só comprador; consignado tem select/update apenas nas linhas
consignadas (caveat aceito: por RLS de linha, via API ele leria o custo real — a UI não mostra).

## Regras de cálculo (método da planilha-base do Ulisses — NÃO alterar sem pedido)

- Comissão = % × (preço + frete interno JP). **Total fornecedor** (entra no acerto ¥) =
  preço + frete JP + comissão.
- **Frete Japão→Brasil**: sempre entra no custo final do produto; entra TAMBÉM no acerto com o
  fornecedor **somente se** `frete_br_pagador='vendedor'`. O form obriga escolher o pagador.
- Custo final R$ = custo final ¥ × taxa de referência (`config.taxa`, hoje 0,032).
- **Lotes** (`compras.itens`): preço/frete JP/comissão únicos no lote; cada item tem rateio ¥
  (`custoY`), frete BR + pagador e status de entrega próprios. `sincronizarVendasComCompras()`
  cria/atualiza UMA venda por item (e uma por compra simples); roda no login/salvar/realtime,
  só para o comprador. Item `entregue_brasil` → venda vira `disponivel`.
- **Consignação (Diego)**: status de venda `consignacao` exige custo declarado; comissão do
  Diego = 50% × (venda − custo declarado); `lucroV(v)` = base − (custo+extras) − comissão —
  use `lucroV`/`custoTotalV` em qualquer conta nova de lucro/estoque, nunca `v.custo` cru.
- **Parte de pagamento**: produto recebido vira nova venda `disponivel` com custo = valor de
  entrada, e o valor soma no `recebido` da venda original.
- Convenção visual **kuroji/akaji**: positivos em tinta índigo (`--ok`), negativos em vermelhão
  (`--bad`). Não existe verde no sistema.

## Design ("Daifukuchō" — livro-caixa japonês)

Paleta: índigo aizome `#1E2C4C`/`#131F38`, washi `#EFEDE3`, latão `#8F6B1F`, vermelhão shu
`#B7392C`. Fontes: Shippori Mincho (display), Instrument Sans (corpo), Spline Sans Mono
(números). Assinatura: hanko 勘定 no login e no cartão do saldo; sidebar-lombada com 勘定帳
vertical. Os NOMES antigos das variáveis CSS (`--ink`, `--brass`, `--ok`…) foram mantidos com
valores novos — estilos inline no JS dependem deles. `dialog{margin:auto}` é necessário
(o reset global mata a centralização nativa).

## Cuidados ao mexer

- Sempre conferir o saldo do fluxo Japão após mudanças em compras/pagamentos. Referência
  histórica: planilha-base fechava em **¥ −663.418,05** (17 lançamentos); desde 19/08 há
  pagamentos novos lançados pelo usuário — o número vivo é o do banco, não o da planilha.
- Testar como os três perfis (botões "Ver como vendedor"/"Ver como consignado" simulam sem senha).
- Preview local sem login: sirva a pasta com `python -m http.server` e injete dados demo
  (ver memória do projeto); nunca digite senhas reais em testes automatizados.
- O e-mail de recuperação de senha só chega para membros da organização Supabase (SMTP
  embutido); para Samuel/Diego receberem, configurar SMTP próprio (ex.: Resend).
- Memória de projeto do Claude: `C:\Users\ULISSES\.claude\projects\C--PROJETOS-CLAUDE-JAPAO\memory\`.
  Histórico da conversa original: `C:\PROJETOS CLAUDE\JAPAO\conversa-japao-historico.md`.
