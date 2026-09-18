## O que muda

<!-- 1-3 linhas. Qual problema resolve? -->

## Tipo
- [ ] feat
- [ ] fix
- [ ] chore / docs
- [ ] migration de banco

## Checklist (obrigatorio)
- [ ] Trabalhei numa branch propria (nunca em `main`/`producao`) e fiz `git pull --rebase` na base antes de abrir o PR
- [ ] Este PR toca **somente** o projeto Supabase deste repositorio (ref em `.claude/guard.json`)
- [ ] Mudanca de banco esta em `supabase/migrations/` com timestamp - **nada aplicado a mao em producao**
- [ ] Nao sobrescrevi trabalho de outra pessoa (conferi `git log origin/<base>` e os PRs abertos)
- [ ] Testei localmente / build passa
- [ ] Sem segredo, token ou `.env` no diff

## Como testar

## Evidencias (screenshots, logs)
