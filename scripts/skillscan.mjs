#!/usr/bin/env node
// skillscan: read a skill / repo BEFORE you install it. Zero dependencies, Node 18+.
// Part of file-guard. Rule tables derived from NVIDIA SkillSpector (Apache-2.0), see NOTICE.
// Usage: node skillscan.mjs <folder | .zip | github url> [--json] [--all] [--detonate] [--with-skillspector]
// Exit: 0 CLEAN, 1 REVIEW, 2 BLOCK, 3 could not scan.
import { readFileSync, writeFileSync, readdirSync, lstatSync, existsSync, mkdtempSync, mkdirSync, rmSync, statSync } from 'node:fs';
import { join, extname, basename, relative, resolve, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { deepFile, parseDeps, osvCheck, realYara } from './deepscan.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2), flag = n => argv.includes('--' + n), target = argv.find(a => !a.startsWith('--'));
if (!target) { console.log('Usage: skillscan.mjs <folder | .zip | github url> [--json] [--all] [--detonate] [--with-skillspector]'); process.exit(3); }

// ---------- rules ----------
const DB = JSON.parse(readFileSync(join(HERE, 'skillscan-rules.json'), 'utf8'));
const RULES = DB.rules.map(r => ({ ...r, rx: new RegExp(r.re, r.flags), only: r.re.startsWith('^[a-zA-Z][a-zA-Z0-9_-]*') && r.re.length < 30 ? /(^|\/)requirements[^/]*\.txt$/i : null }));
// own rules on top of the SkillSpector tables: obfuscation, hidden characters, install hooks, binaries
const OWN = [
  { id: 'H1', fam: 'Hidden Content', kind: 'any', w: 0.9, rx: /[\u200B\u202A-\u202E\u2060-\u2064\uFEFF]|[\u{E0000}-\u{E007F}]/u, why: 'invisible characters: text a person cannot see but the agent reads' },
  { id: 'H2', fam: 'Hidden Content', kind: 'any', w: 0.5, rx: /[\u200C\u200D\u200E\u200F]{2,}|[A-Za-z][\u200C\u200D][A-Za-z]/u, why: 'joiner / direction marks inside plain text (normal in emoji and some scripts, odd elsewhere)' },
  { id: 'X1', fam: 'Remote Execution', kind: 'any', w: 0.9, rx: /\b(?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod|irm)\b[^\n|]{0,160}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\b(?:powershell|pwsh)(?:\.exe)?\s+[^\n]{0,40}-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}|\biex\b\s*\(?\s*(?:\(?new-object|iwr|irm|curl)|\bbase64\s+(?:-d|--decode)\b[^\n|]{0,80}\|\s*(?:ba|z)?sh\b/i, why: 'downloads or decodes something and runs it straight away' },
  // changes to the agent's own rule/memory files, and switching off its safeguards (file-guard's home turf)
  { id: 'M1', fam: 'Memory Poisoning', kind: 'any', w: 0.7, rx: /\b(?:append|add|write|insert|put|save|store|inject|include|paste|copy)\b[^\n]{0,80}\b(?:AGENTS|SOUL|MEMORY|IDENTITY|TOOLS|USER|HEARTBEAT|HEARTBEAT|CLAUDE|GEMINI)\.md\b|\b(?:AGENTS|SOUL|MEMORY|IDENTITY|TOOLS|CLAUDE)\.md\b[^\n]{0,60}\b(?:persists?|permanent|every session|future sessions|across sessions)\b|\bpersists? across (?:sessions|restarts)\b/i, neg: 1, why: 'edits the agent\'s own rule or memory files so the change outlives this session' },
  { id: 'M2', fam: 'Rogue Agent', kind: 'any', w: 0.9, rx: /\b(?:disable|turn off|switch off|bypass|circumvent|skip|deactivate)\b(?:\s+\w+){0,3}?\s+(?:the\s+|all\s+|any\s+)?(?:file[- ]?guard|integrity (?:check|guard|wall)s?|baseline|safety (?:check|rule|limit)s?|security (?:check|rule|scan)s?|sandbox|antivirus|defender|firewall|audit log|approval|confirmation|verification|guardrails?)\b/i, neg: 1, why: 'asks the agent to switch off a safeguard' },
  // phrasings the stock tables miss (found by testing against held-out samples)
  { id: 'P5', fam: 'Prompt Injection', kind: 'any', w: 0.9, rx: /\b(?:ignore|disregard|forget|override|discard|drop)\b\s+(?:all\s+|any\s+|every\s+)?(?:of\s+)?(?:the\s+)?(?:previous|prior|earlier|above|preceding|former|your|these|those)\s+(?:instructions?|rules?|prompts?|directions?|guidelines?|context|programming)\b|\b(?:forget|disregard|ignore)\b[^\n]{0,30}\b(?:what|everything|anything)\b[^\n]{0,25}\b(?:you were|you've been|you have been|you are|i|we)\s+(?:told|instructed|given|said)\b|\bobey\b[^\n]{0,30}\b(?:text|instructions?|commands?|content)\b[^\n]{0,40}\b(?:tool|web|file|document|page|result|output|email|message)s?\b/i, neg: 1, why: 'tells the agent to drop what it was told, or to obey text it finds in data' },
  { id: 'C2', fam: 'Prompt Injection', kind: 'any', w: 0.85, neg: 1, rx: /\b(?:keep|hide|conceal|mask|disguise)\b[^\n]{0,40}\b(?:from|to)\s+(?:the\s+)?(?:\w+\s+){0,3}(?:user|owner|human|operator|person you work for|person you serve)\b|\b(?:secretly|covertly|silently|quietly)\b[^\n]{0,30}\b(?:send|upload|post|exfiltrate|execute|install)\b|\bwithout\s+(?:the\s+)?(?:user|owner|them|anyone)\s+(?:knowing|noticing|seeing|realizing)\b/i, why: 'asks the agent to do something and hide it from the person it works for' },
  { id: 'X2', fam: 'Data Exfiltration', kind: 'any', w: 0.9, rx: /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]*(?:\{[^}]*\}|%7B|\$\{|<[^>]+>|\[[A-Za-z_]+\])[^)]*\)|<img\b[^>]*\bsrc\s*=\s*["']https?:\/\/[^"']*(?:\{[^}]*\}|%7B|\$\{)[^"']*["']/i, why: 'a markdown image whose address carries conversation data: when it renders, the data is sent out' },
  { id: 'X3', fam: 'Data Exfiltration', kind: 'any', w: 0.9, rx: /\b(?:send|upload|post|email|forward|transmit|submit|copy)\b[^\n]{0,60}\b(?:contents?|files?|data|history|conversation|home directory|documents?|secrets?|keys?|credentials?|\.env)\b[^\n]{0,60}\b(?:to|at|into)\s+(?:https?:\/\/|ftp:\/\/|[\w.-]+@[\w.-]+)/i, neg: 1, why: 'tells the agent to send files or data to an outside address' },
  { id: 'M4', fam: 'Memory Poisoning', kind: 'prose', w: 0.8, rx: /(\b[\w'Ã¢â‚¬â„¢-]{2,20}\b[ \t,.;]{0,3}?)\1{25,}/, why: 'the same words repeated dozens of times, a way to push the real instructions out of the agent\'s context' },
  { id: 'M3', fam: 'Excessive Agency', kind: 'any', w: 0.85, rx: /\b(?:never|do not|don't|without)\s+(?:ever\s+)?(?:ask|asking|wait|waiting|check|checking)\b[^\n]{0,30}\b(?:user|owner|human|operator|me)\b[^\n]{0,30}\b(?:approval|permission|confirmation|consent|first)\b|\balways trust\b[^\n]{0,40}\b(?:skill|file|source|script|tool|instructions?)\b/i, why: 'tells the agent to act without the owner\'s approval' },
];
// one file that both READS something private and SENDS data out is worse than either alone (a cheap version of taint tracking)
const SENSITIVE = /['"]\.(?:ssh|aws|gnupg|kube|netrc|npmrc|docker)['"]|\.(?:ssh|aws|gnupg|kube)[\\/]|(?:~|\$HOME|%USERPROFILE%|os\.path\.expanduser\(['"]~)[^\n'"]{0,6}[\\/]?\.?(?:ssh|aws|gnupg|kube|docker|npmrc|netrc|env|config[\\/]gcloud)\b|\bid_(?:rsa|ed25519)\b|(?<!process)\.env\b(?!\.|\[)|\bcredentials\.json\b|\.aws[\\/]credentials|keychain|login data|cookies\.sqlite|wallet\.dat|\bprintenv\b|\bdict\(os\.environ\)|\bos\.environ\.copy\(|JSON\.stringify\(process\.env\)|Object\.(?:keys|entries|assign)\([^)]*process\.env\)|\{\s*\.\.\.process\.env\s*\}/i;
const SENDS = /\brequests\.(?:post|put)\b|\burllib\.request\.urlopen\b|\bhttp\.client\b|\bsocket\.(?:connect|create_connection)\b|\bfetch\s*\([^)]*(?:method\s*:\s*['"]?(?:POST|PUT)|body\s*:)|\baxios\.(?:post|put)\b|\bcurl\b[^\n]{0,80}(?:-d\b|--data|-F\b|-T\b|--upload)|\bInvoke-(?:WebRequest|RestMethod)\b[^\n]{0,80}-Method\s+(?:Post|Put)|\b(?:nc|ncat|netcat)\s+\S+\s+\d+|\bscp\b[^\n]{0,40}@|\bhttp\.request\b|\bsmtplib\b|webhook/i;
const FAMS = { ...DB.why, 'Hidden Content': 'Text a person cannot see but the agent reads.', 'Remote Execution': 'Downloads or decodes something and runs it at once.', 'Package Hooks': 'Runs commands automatically when the package is installed.', 'Binary File': 'A compiled program inside a skill: nothing here can be read or reviewed.' };

// ---------- helpers ----------
const CODE_EXT = new Set(['.py', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.sh', '.bash', '.zsh', '.ps1', '.psm1', '.bat', '.cmd', '.rb', '.pl', '.php', '.go', '.rs', '.java', '.lua', '.vbs']);
const PROSE_EXT = new Set(['.md', '.markdown', '.txt', '.rst', '.mdx', '']);
const DATA_EXT = new Set(['.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.xml', '.html', '.htm', '.csv']);
const SKIP_DIR = new Set(['node_modules', '.git', '__pycache__', '.venv', 'dist-info']);
const MAXF = 1024 * 1024;
const txt = b => ((x => (x.charCodeAt(0) === 0xFEFF ? x.slice(1) : x))(b[0] === 0xFF && b[1] === 0xFE ? b.subarray(2).toString('utf16le') : b[0] === 0xFE && b[1] === 0xFF ? Buffer.from(b.subarray(2)).swap16().toString('utf16le') : b.toString('utf8').replace(/\0/g, '')));
const isBinary = b => (b[0] === 0x4D && b[1] === 0x5A) || (b[0] === 0x7F && b[1] === 0x45 && b[2] === 0x4C && b[3] === 0x46) || (b[0] === 0xCF && b[1] === 0xFA && b[2] === 0xED) || (b[0] === 0xCA && b[1] === 0xFE && b[2] === 0xBA);
const LEGAL = /(^|\/)(LICEN[CS]E|COPYING|NOTICE|OFL|PATENTS|CODE_OF_CONDUCT)[^/]*$|-OFL\.txt$/i;
const sha = b => createHash('sha256').update(b).digest('hex');

// ---------- input: folder, zip or github url ----------
async function resolveInput(t) {
  if (/^https?:\/\//i.test(t)) {
    const m = t.match(/github\.com\/([^/]+)\/([^/#?]+?)(?:\.git)?(?:\/tree\/([^/]+))?(?:[/?#].*)?$/i);
    const url = m ? `https://github.com/${m[1]}/${m[2]}/archive/${m[3] || 'HEAD'}.zip` : t;
    const r = await fetch(url, { redirect: 'follow' }); if (!r.ok) throw new Error('download failed: HTTP ' + r.status);
    const tmp = mkdtempSync(join(tmpdir(), 'skillscan-')), zip = join(tmp, 'in.zip'); writeFileSync(zip, Buffer.from(await r.arrayBuffer()));
    return unzip(zip, tmp);
  }
  const p = resolve(t); if (!existsSync(p)) throw new Error('not found: ' + p);
  if (statSync(p).isDirectory()) return { root: p, cleanup: () => {} };
  if (/\.zip$/i.test(p)) return unzip(p, mkdtempSync(join(tmpdir(), 'skillscan-')));
  return { root: dirname(p), only: p, cleanup: () => {} };
}
function unzip(zip, tmp) {
  const out = join(tmp, 'x'); mkdirSync(out, { recursive: true });
  let r = spawnSync('tar', ['-xf', zip, '-C', out], { encoding: 'utf8' });
  if (r.status !== 0) r = process.platform === 'win32' ? spawnSync('powershell', ['-NoProfile', '-Command', `Expand-Archive -LiteralPath '${zip}' -DestinationPath '${out}' -Force`]) : spawnSync('unzip', ['-q', zip, '-d', out]);
  if (r.status !== 0) throw new Error('could not unpack the zip (need tar, unzip or PowerShell)');
  return { root: out, cleanup: () => rmSync(tmp, { recursive: true, force: true }) };
}
function walk(p, out = []) { let es = []; try { es = readdirSync(p); } catch { return out; } for (const e of es) { if (SKIP_DIR.has(e)) continue; const f = join(p, e); let st; try { st = lstatSync(f); } catch { continue; } if (st.isSymbolicLink()) out.push({ f, link: true }); else if (st.isDirectory()) walk(f, out); else out.push({ f, size: st.size }); } return out; }

// ---------- obfuscation: scan what a person sees AND what the file turns into ----------
function variants(t) {
  const v = [[t, '']];
  const n = t.normalize('NFKC').replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]|[\u{E0000}-\u{E007F}]/gu, '').replace(/\$\{[^}]*\}|\$IFS|\$[@*0-9]|\$\(\)|[`'"\\^]/g, '');
  if (n !== t && n.length > 3) v.push([n, 'after removing invisible characters / shell obfuscation']);
  const ls = t.replace(/([A-Za-z])[ _.-](?=[A-Za-z][ _.-]|[A-Za-z]\b)/g, '$1'); if (ls !== t && /ignore|instruction|disregard/i.test(ls) && !/ignore|instruction|disregard/i.test(t)) v.push([ls, 'after joining letter-spaced text']);
  for (const m of t.matchAll(/[A-Za-z0-9+/]{24,}={0,2}/g)) { try { const d = Buffer.from(m[0], 'base64').toString('utf8'); if (/^[\t\r\n\x20-\x7e]{12,}$/.test(d)) v.push([d, 'after decoding base64']); } catch {} }
  for (const m of t.matchAll(/(?:\\x[0-9a-fA-F]{2}){8,}|(?:%[0-9a-fA-F]{2}){8,}/g)) { try { const d = m[0].startsWith('%') ? decodeURIComponent(m[0]) : m[0].replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))); if (/^[\t\r\n\x20-\x7e]{8,}$/.test(d)) v.push([d, 'after decoding hex/url escapes']); } catch {} }
  return v;
}

// ---------- context: the part that cuts false alarms ----------
const NEG_BEFORE = /(?:\bnever|\bdo not|\bdon'?t|\bmust not|\bmustn'?t|\bshould not|\bshouldn'?t|\bavoid|\bwithout|\brefuse to|\bnot to|\bno longer|\bprevent|\bblock|\breject|\bdetects?|\bflags?|\bscans? for|\battackers? (?:write|say|use|try)|\bphrases? such as|\bexamples? of|\be\.g\.,?)\s+(?:["'`(\w-]+\s+){0,2}["'`(]?$/i;
const PLACEHOLDER = /YOUR[_ -]|<[^>\n]{1,30}>|\bexample\b|placeholder|\$\{?[A-Z][A-Z0-9_]{3,}\}?|process\.env|os\.environ|getenv|\bxxx+\b|\.\.\.|\bTODO\b|\bchangeme\b/i;
const ACTION = /\b(?:send|post|upload|exfil\w*|steal|dump|leak|forward|transmit|extract|collect|harvest|read|cat|copy|curl|wget|scp|print|echo|cp|include|attach|share|email|paste|reveal|show|embed|base64|zip|tar)\b/i;
const SECRETISH = /\b(?:credentials?|secrets?|passwords?|tokens?|api[_ -]?keys?|private key|ssh|\.env|id_rsa|keychain|cookies?|wallet|mnemonic|seed phrase)\b/i;
const CONCEAL = /(?:never|do not|don't|without)\s+(?:\w+\s+){0,3}(?:tell|mention|inform|reveal|disclose|notify|show|ask)\s+(?:\w+\s+){0,3}(?:the\s+)?(?:user|owner|human|them|anyone|operator)|(?:hide|conceal|keep secret)\s+(?:this|these|it|that)/i;

function judge(rule, line, idx, inFence, fileKind) {
  // returns [factor, note]; factor 1 = full weight
  let f = 1, notes = [];
  const before = line.slice(Math.max(0, idx - 60), idx);
  const inQuote = (line.slice(0, idx).match(/[`"Ã¢â‚¬Å“Ã¢â‚¬ÂÃ¢â‚¬ËœÃ¢â‚¬â„¢']/g) || []).length % 2 === 1;
  if ((rule.neg || /^(?:EA2|M2|M3)$/.test(rule.id)) && !CONCEAL.test(line)) { if (NEG_BEFORE.test(before)) { f *= 0.1; notes.push('negated, as in a warning'); } else if (inQuote) { f *= 0.3; notes.push('quoted as an example'); } }
  if (fileKind === 'prose' && !inFence && /^(?:PE3|E[1-5]|AS\d|SC1)$/.test(rule.id)) { // credential/exfil wording in prose counts only when somebody is told to DO something with a secret
    if (!(ACTION.test(line) && SECRETISH.test(line))) { f *= 0.2; notes.push('mentions a secret but no one is told to read or send it'); }
  }
  if (rule.id === 'PE3' && !ACTION.test(line)) { f *= 0.5; notes.push('names a credential store but nothing reads or sends it'); }
  if (PLACEHOLDER.test(line) && /^(?:PE3|SC1)$/.test(rule.id) && !CONCEAL.test(line) && !SENDS.test(line)) { f *= 0.4; notes.push('placeholder / environment variable, not a real secret'); }
  return [f, notes];
}

// ---------- scan one file ----------
function scanText(rel, text, kind) {
  const out = [], lines = text.split(/\r?\n/), fence = []; let inF = false, fenceLang = '';
  for (let i = 0; i < lines.length; i++) { if (kind === 'prose' && /^\s{0,3}(`{3,}|~{3,})\s*([\w-]*)/.test(lines[i])) { inF = !inF; fenceLang = inF ? (lines[i].match(/^\s{0,3}(?:`{3,}|~{3,})\s*([\w-]*)/)[1] || '') : ''; fence.push(null); continue; } fence.push(inF); }
  const seenKey = new Set();
  for (const [vt, how] of variants(text)) {
    const vl = how ? [vt] : lines;
    vl.forEach((ln, i) => {
      const inFence = how ? false : fence[i] === true, k = how ? 'any' : kind;
      const chunks = [ln]; if (!how && kind === 'prose' && !inFence && lines[i + 1] && fence[i + 1] === false) chunks.push(ln + ' ' + lines[i + 1]);
      for (const c of chunks) {
        if (c.length > 4000) continue;
        for (const r of [...RULES, ...OWN.map(o => ({ ...o, rx: o.rx }))]) {
          if (r.only && !r.only.test(rel)) continue;
          if (/^P[6-9]$/.test(r.id) && k === 'code') continue; // 'return PROMPT' in code is not a leak
          if (r.kind === 'code' && !(k === 'code' || inFence || how)) continue;
          if (r.kind === 'prose' && !(k === 'prose' && !inFence || how)) continue;
          const m = r.rx.exec(c); if (!m) continue;
          const key = r.id + '|' + (how ? 'v' : i) + '|' + m[0].slice(0, 30); if (seenKey.has(key)) continue; seenKey.add(key);
          const [f, notes] = judge(r, c, m.index, inFence, kind);
          const score = Math.min(1, r.w * f + (how ? 0.05 : 0));
          out.push({ file: rel, line: how ? 0 : i + 1, id: r.id, fam: r.fam, score, base: r.w, text: m[0].slice(0, 100), how, why: r.why || FAMS[r.fam] || '', notes, inFence });
        }
      }
    });
  }
  out.codeText = lines.filter((_, i) => kind === 'code' || fence[i] === true).join('\n');
  return out;
}

// ---------- main ----------
const { root, only, cleanup } = await resolveInput(target).catch(e => { console.error('skillscan: ' + e.message); process.exit(3); });
const files = (only ? [{ f: only, size: statSync(only).size }] : walk(root)), byHash = new Map(), findings = [], extra = [], skipped = [], allDeps = [];
for (const e of files) {
  const rel = relative(root, e.f).replace(/\\/g, '/') || basename(e.f);
  if (e.link) { findings.push({ file: rel, line: 0, id: 'L1', fam: 'Hidden Content', score: 0.7, text: 'symbolic link', why: 'a link can point outside the skill folder', notes: [] }); continue; }
  if (e.size > MAXF) { skipped.push(rel + ' (over 1 MB)'); continue; }
  let b; try { b = readFileSync(e.f); } catch { skipped.push(rel + ' (unreadable)'); continue; }
  const h = sha(b); if (byHash.has(h)) { byHash.get(h).dups.push(rel); continue; } byHash.set(h, { rel, dups: [] });
  if (isBinary(b)) { findings.push({ file: rel, line: 0, id: 'B1', fam: 'Binary File', score: 0.85, text: 'compiled program', why: FAMS['Binary File'], notes: [] }); continue; }
  const ext = extname(rel).toLowerCase(), t = txt(b);
  if (/\0/.test(b.subarray(0, 512).toString('latin1')) && !/^\xFF\xFE|^\xFE\xFF/.test(b.subarray(0, 2).toString('latin1'))) { skipped.push(rel + ' (binary data)'); continue; }
  const kind = CODE_EXT.has(ext) || /^#!/.test(t) ? 'code' : PROSE_EXT.has(ext) ? 'prose' : DATA_EXT.has(ext) ? 'data' : 'prose';
  if (basename(rel) === 'package.json') { try { const pj = JSON.parse(t); for (const s of ['preinstall', 'install', 'postinstall', 'prepare']) if (pj.scripts?.[s]) findings.push({ file: rel, line: 0, id: 'K1', fam: 'Package Hooks', score: /curl|wget|iwr|http|node\s+-e|powershell|eval|base64/i.test(pj.scripts[s]) ? 0.9 : 0.5, text: `scripts.${s}: ${String(pj.scripts[s]).slice(0, 80)}`, why: FAMS['Package Hooks'], notes: [] }); } catch {} }
  if (LEGAL.test(rel)) continue; // licence text is not an instruction
  const fs_ = scanText(rel, t, kind === 'data' ? 'code' : kind); findings.push(...fs_);
  findings.push(...deepFile(rel, t, kind === 'code')); if (/^(?:package\.json|requirements[\w.-]*\.txt)$/i.test(basename(rel))) { const pd = parseDeps(rel, t); findings.push(...pd.findings); allDeps.push(...pd.deps); }
  { const codeText = fs_.codeText || ''; const sl = codeText.split(/\r?\n/).findIndex(l => SENSITIVE.test(l)), nl = codeText.split(/\r?\n/).findIndex(l => SENDS.test(l)); if (sl >= 0 && nl >= 0) findings.push({ file: rel, line: nl + 1, id: 'C1', fam: 'Data Exfiltration', score: 0.95, text: 'reads a private file/secret (line ' + (sl + 1) + ') and sends data out (line ' + (nl + 1) + ')', why: 'the same script collects private data and sends it over the network', notes: [] }); }
}
const cov = { structure: 'js/py token-level', yaraLite: true, deps: allDeps.length + ' declared', osv: 'not asked (add --online)', yara: 'not asked (add --yara <rules.yar>)' };
if (flag('online')) { const o = await osvCheck(allDeps); findings.push(...o.findings); cov.osv = o.ran ? `asked about ${o.asked} pinned package(s)` : `FAILED (${o.error})`; }
const yi = argv.indexOf('--yara'); if (yi >= 0 && argv[yi + 1]) { const y = realYara(root, resolve(argv[yi + 1])); findings.push(...y.findings); cov.yara = y.ran ? 'real YARA ran' : 'yara program not found or failed'; }
cleanup();

// ---------- allow-list (given on the command line, never read from the folder being scanned) ----------
const allowArg = (() => { const i = argv.indexOf('--allow'); return i >= 0 ? (argv[i + 1] || '') : ''; })();
const ALLOW = allowArg.split(',').filter(Boolean).map(s => { const [id, ...g] = s.split(':'); return { id, file: g.join(':') }; });
const allowed = f => ALLOW.some(a => a.id === f.id && (!a.file || f.file === a.file || f.file.endsWith('/' + a.file)));
for (let i = findings.length - 1; i >= 0; i--) if (allowed(findings[i])) findings.splice(i, 1);
// A single weak signal is not enough to block: generic tool/agency/supply-chain hits are capped at MEDIUM
// unless a decisive finding from another family backs them up in the same skill.
const WEAK = /^(?:TM|EA|OH|SC|AS|RA|PE[1245]|AR2|MP[123]|P[6-9]|H2|K1)/, DECISIVE = /^(?:P[1-5]|H1|X1|C1|M\d|AR|E\d|B1|PE3|L1)/;
const strong = findings.filter(f => f.score >= 0.85 && DECISIVE.test(f.id));
for (const f of findings) if (WEAK.test(f.id) && f.score > 0.75 && !(f.id === 'K1' && f.score >= 0.9) && !strong.some(s => s.fam !== f.fam)) { f.notes = [...(f.notes || []), 'single weak signal, capped']; f.score = /\.(?:md|markdown|txt|rst|mdx)$/i.test(f.file) ? Math.min(f.score, 0.55) : 0.75; }

// ---------- group, score, verdict ----------
const groups = new Map();
for (const f of findings) { const k = f.id + '|' + f.file; const g = groups.get(k); if (!g) groups.set(k, { ...f, lines: f.line ? [f.line] : [], count: 1 }); else { g.count++; if (f.line && g.lines.length < 4) g.lines.push(f.line); if (f.score > g.score) { g.score = f.score; g.text = f.text; g.notes = f.notes; } } }
const G = [...groups.values()].sort((a, b) => b.score - a.score);
const sev = s => s >= 0.85 ? 'HIGH' : s >= 0.6 ? 'MEDIUM' : s >= 0.3 ? 'LOW' : 'NOTE';
const hi = G.filter(g => g.score >= 0.85), med = G.filter(g => g.score >= 0.6 && g.score < 0.85);
const famsHi = new Set(hi.map(g => g.fam));
let verdict = hi.length ? 'BLOCK' : med.length ? 'REVIEW' : 'CLEAN';
const dupNote = [...byHash.values()].filter(x => x.dups.length).reduce((n, x) => n + x.dups.length, 0);

// ---------- optional: run next to skillspector / detonate ----------
let ss = null;
if (flag('with-skillspector')) { const r = spawnSync('skillspector', ['scan', root, '--no-llm'], { encoding: 'utf8', timeout: 300000, shell: process.platform === 'win32' }); const t = (r.stdout || '') + (r.stderr || ''); ss = { ran: r.status !== null && !r.error, high: (t.match(/\bHIGH:/g) || []).length, critical: (t.match(/\bCRITICAL:/g) || []).length, medium: (t.match(/\bMEDIUM:/g) || []).length, reco: (t.match(/Recommendation\s+(.+)/) || [])[1]?.trim() || '' }; }
let det = null;
if (flag('detonate')) { const dt = join(HERE, 'detonate.mjs'); if (existsSync(dt)) { const r = spawnSync(process.execPath, [dt, root], { encoding: 'utf8', timeout: 240000 }); det = (r.stdout || r.stderr || '').trim().split('\n').slice(-12).join('\n'); } else det = 'detonate.mjs not found next to skillscan'; }

if (flag('json')) { console.log(JSON.stringify({ verdict, scanned: byHash.size, duplicatesSkipped: dupNote, skipped, findings: G.map(g => ({ severity: sev(g.score), score: +g.score.toFixed(2), rule: g.id, family: g.fam, file: g.file, lines: g.lines, count: g.count, text: g.text, why: g.why, notes: g.notes, decoded: g.how || undefined })), skillspector: ss, detonate: det, coverage: cov }, null, 1)); process.exit(verdict === 'BLOCK' ? 2 : verdict === 'REVIEW' ? 1 : 0); }

const ICON = { BLOCK: 'BLOCK  - do not install', REVIEW: 'REVIEW - read the findings first', CLEAN: 'CLEAN  - nothing that looks harmful' };
console.log(`skillscan: ${ICON[verdict]}`);
console.log(`scanned ${byHash.size} file(s)${dupNote ? `, ${dupNote} identical copy/copies counted once` : ''}${skipped.length ? `, skipped ${skipped.length}` : ''}`);
const show = flag('all') ? G : G.filter(g => g.score >= 0.3).slice(0, 12), hidden = G.length - show.length;
for (const g of show) {
  console.log(`\n[${sev(g.score)}] ${g.fam} (${g.id})  ${g.file}${g.lines.length ? ':' + g.lines.join(',') : ''}${g.count > g.lines.length && g.lines.length ? ` +${g.count - g.lines.length} more` : ''}`);
  console.log(`   found : ${g.text.replace(/\s+/g, ' ')}${g.how ? `  (${g.how})` : ''}`);
  if (g.why) console.log(`   why   : ${g.why}`);
  if (g.notes?.length) console.log(`   lowered: ${g.notes.join('; ')}`);
}
if (hidden > 0) console.log(`\n${hidden} minor note(s) hidden (use --all).`);
if (ss) console.log(`\nSkillSpector on the same folder: ${ss.ran ? `${ss.critical} CRITICAL, ${ss.high} HIGH, ${ss.medium} MEDIUM${ss.reco ? ' - ' + ss.reco : ''}` : 'not installed or failed'}`);
if (det) console.log('\nDetonation (script run in a sealed container):\n' + det);
console.log(`\nChecked: text rules, structure scan (${cov.structure}), yara-lite signatures, dependencies (${cov.deps}), OSV: ${cov.osv}, real YARA: ${cov.yara}.`);
console.log('NOT checked: real syntax trees, code that only exists after download, obfuscation beyond string pieces/escapes/base64, native binaries beyond a flag. CLEAN is not proof of safety. Use --detonate for scripts.');
process.exit(verdict === 'BLOCK' ? 2 : verdict === 'REVIEW' ? 1 : 0);
