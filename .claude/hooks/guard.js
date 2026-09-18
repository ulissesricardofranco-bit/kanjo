#!/usr/bin/env node
// Trava de segurança do projeto (PreToolUse hook do Claude Code).
// 1) Bloqueia qualquer referência a um projeto Supabase que não seja o deste repositório.
// 2) Exige confirmação humana para escrita no banco (SQL de escrita, migrations, db push).
// 3) Bloqueia commit/push/merge direto nas branches protegidas, force-push e comandos destrutivos.
// Config: .claude/guard.json  { "supabaseRef": "...", "protectedBranches": ["main"] }
'use strict';
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const KNOWN_REFS = {
  majbeneopptzppzkzyqd: 'DENFA-GESTAO',
  pjefemrdimhaqzjwajrq: 'DENFA-RH',
  uugbjirgvmpxycqjwtda: 'denfa-service-hub (SAC / care-hub)',
  wjndmqesmqjurgzxhspl: 'denfa-portal',
  hzlpicbocgsdfuifanqs: 'JAPAO (kanjo / INSTRUMENTOS)',
};

function out(decision, reason) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: decision, permissionDecisionReason: reason },
  }));
  process.exit(0);
}
const deny = (r) => out('deny', 'TRAVA: ' + r);
const ask = (r) => out('ask', 'CONFIRMAR: ' + r);

let input = '';
try { input = fs.readFileSync(0, 'utf8'); } catch (_) {}
let ev = {};
try { ev = JSON.parse(input || '{}'); } catch (_) { process.exit(0); }

const projectDir = process.env.CLAUDE_PROJECT_DIR || ev.cwd || process.cwd();
let cfg = {};
try { cfg = JSON.parse(fs.readFileSync(path.join(projectDir, '.claude', 'guard.json'), 'utf8')); } catch (_) {}
const myRef = cfg.supabaseRef || '';
const protectedBranches = cfg.protectedBranches || ['main'];

const tool = ev.tool_name || '';
const ti = ev.tool_input || {};
const blob = JSON.stringify(ti);

// ---------- 1) ref de Supabase de OUTRO projeto ----------
for (const ref of Object.keys(KNOWN_REFS)) {
  if (ref !== myRef && blob.includes(ref)) {
    deny('referencia ao projeto Supabase "' + KNOWN_REFS[ref] + '" (' + ref + ') dentro do projeto "' + (KNOWN_REFS[myRef] || myRef || '?') + '". Abra a sessao na pasta certa.');
  }
}
// qualquer outro ref desconhecido em URL supabase
const m = blob.match(/([a-z]{20})\.supabase\.(co|com|in)/g) || [];
for (const hit of m) {
  const ref = hit.slice(0, 20);
  if (myRef && ref !== myRef && !KNOWN_REFS[ref]) deny('URL Supabase de projeto desconhecido (' + ref + '); este repositorio usa ' + myRef + '.');
}

// ---------- 2) escrita no banco ----------
const WRITE_SQL = /\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|GRANT|REVOKE)\b/i;
if (/^mcp__supabase__/.test(tool)) {
  if (/apply_migration|deploy_edge_function|create_branch|merge_branch|reset_branch|rebase_branch|delete_branch|create_project|pause_project|restore_project/.test(tool)) {
    ask(tool + ' altera o projeto Supabase ' + myRef + '. Confirme que e o banco certo e que isso passa por PR/migration versionada.');
  }
  if (/execute_sql/.test(tool) && WRITE_SQL.test(String(ti.query || ti.sql || blob))) {
    ask('SQL de ESCRITA direto no banco ' + myRef + ' via MCP. Prefira migration em supabase/migrations + PR. Confirme para continuar.');
  }
  process.exit(0);
}

if (tool !== 'Bash') process.exit(0);
const cmd = String(ti.command || '');
const has = (re) => re.test(cmd);

// supabase CLI
if (has(/\bsupabase\b.*\blink\b/) && myRef && !cmd.includes(myRef)) deny('"supabase link" sem --project-ref ' + myRef + '.');
if (has(/\bsupabase\b.*\bdb\s+reset\b/)) deny('"supabase db reset" apaga o banco. Nao e permitido por aqui.');
if (has(/\bsupabase\b.*\b(db\s+push|migration\s+up|db\s+dump|functions\s+deploy|secrets\s+set)\b/)) ask('"' + cmd.slice(0, 120) + '" altera o Supabase ' + myRef + '. O padrao e migration versionada + PR. Confirme.');
if (has(/\bpsql\b/) && WRITE_SQL.test(cmd)) ask('psql com SQL de escrita. Confirme o banco e prefira migration + PR.');

// git
if (has(/\bgit\b/)) {
  let branch = '';
  try { branch = execSync('git rev-parse --abbrev-ref HEAD', { cwd: projectDir, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim(); } catch (_) {}
  const onProtected = protectedBranches.includes(branch);
  const targetsProtected = protectedBranches.some((b) => new RegExp('(^|[\\s:/])' + b + '(\\s|$)').test(cmd));
  const prot = protectedBranches.join('/');

  if (has(/\bgit\s+push\b.*(\s--force\b|\s-f\b|\s--force-with-lease\b)/) && (targetsProtected || onProtected)) deny('force-push em branch protegida. Nunca reescreva historico compartilhado.');
  if (has(/\bgit\s+push\b.*(\s--force(?!-with-lease)\b|\s-f\b)/)) deny('force-push. Se precisar, use --force-with-lease so na sua propria branch de feature.');
  if (has(/\bgit\s+push\b/) && targetsProtected) deny('push direto para ' + prot + '. Suba a branch e abra PR (gh pr create).');
  if (has(/\bgit\s+push\b/) && onProtected) deny('voce esta em "' + branch + '" (protegida). Crie uma branch: git switch -c feat/<nome>');
  if (has(/\bgit\s+commit\b/) && onProtected) deny('commit direto em "' + branch + '". Fluxo: git switch -c feat/<nome> -> commit -> push -> gh pr create.');
  if (has(/\bgit\s+merge\b/) && onProtected) deny('merge local em "' + branch + '". Merges em branch protegida so via PR no GitHub.');
  if (has(/\bgit\s+rebase\b/) && onProtected) deny('rebase em "' + branch + '" (protegida).');
  if (has(/\bgit\s+reset\s+--hard\b/)) deny('git reset --hard descarta trabalho. Use git stash ou git restore <arquivo>.');
  if (has(/\bgit\s+clean\b.*\s-[a-zA-Z]*f/)) deny('git clean -f apaga arquivos nao rastreados. Use git stash -u.');
  if (has(/\bgit\s+branch\s+(-D|--delete\s+--force)\b/)) deny('exclusao forcada de branch. Use -d (so depois do merge).');
  if (has(/\bgit\s+push\b.*\s(--delete|-d)\s/) && targetsProtected) deny('exclusao de branch protegida no remoto.');
  if (has(/\bgit\s+commit\b.*--no-verify/)) deny('--no-verify pula os hooks de qualidade.');
  if (has(/\bgit\s+checkout\s+(--\s+)?\.\s*$/) || has(/\bgit\s+restore\s+\.\s*$/)) ask('descarta TODAS as alteracoes locais nao commitadas. Confirme.');
  if (has(/\bgit\s+stash\s+(drop|clear)\b/)) ask('apaga stash (trabalho guardado). Confirme.');
}
process.exit(0);
