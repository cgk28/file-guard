// deepscan: the three layers skillscan.mjs lacked. Zero dependencies, Node 18+.
//  1. structure  - reads code as code (comments and strings taken apart, string pieces re-joined, aliases and
//                  decode-then-run chains followed). Token level, NOT a full parser: honest name "structure scan".
//  2. yara-lite  - signature rules in yara-lite-rules.json (YARA-like: strings + condition). With
//                  --yara <rules.yar> and a `yara` program on PATH the real YARA also runs.
//  3. deps       - package.json / requirements.txt: URL/git deps, unpinned, typosquats, extra package indexes;
//                  with --online it asks OSV.dev (free, no key) for known vulnerabilities.
import { readFileSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const HERE = dirname(fileURLToPath(import.meta.url));
const F = (file, line, id, fam, score, text, why) => ({ file, line, id, fam, score, text: String(text).slice(0, 100), why, notes: [], how: '' });

// ---------------- 1. structure ----------------
const JS = /\.(?:m?js|cjs|jsx|tsx?)$/i, PY = /\.py$/i;
const unesc = s => s.replace(/\\x([0-9a-f]{2})|\\u([0-9a-f]{4})|\\u\{([0-9a-f]+)\}/gi, (_, a, b, c) => String.fromCodePoint(parseInt(a || b || c, 16)));
// split source into code (every string literal replaced by "<index>") and the list of the literals
function split(src, py) {
  let code = '', strs = [], i = 0; const n = src.length;
  while (i < n) {
    const c = src[i], d = src[i + 1];
    if (!py && c === '/' && d === '/') { while (i < n && src[i] !== '\n') i++; continue; }
    if (!py && c === '/' && d === '*') { const e = src.indexOf('*/', i + 2); i = e < 0 ? n : e + 2; continue; }
    if (py && c === '#') { while (i < n && src[i] !== '\n') i++; continue; }
    const tri = py && (src.startsWith('"""', i) || src.startsWith("'''", i));
    if (c === '"' || c === "'" || (!py && c === '`') || tri) {
      const q = tri ? src.substr(i, 3) : c; let j = i + q.length, s = '';
      while (j < n && !src.startsWith(q, j)) { if (src[j] === '\\') { s += src[j] + (src[j + 1] || ''); j += 2; } else s += src[j++]; }
      strs.push(unesc(s)); code += `"${strs.length - 1}"`; i = j + q.length; continue;
    }
    code += c; i++;
  }
  return { code, strs };
}
const lineOf = (src, idx) => src.slice(0, idx).split('\n').length;
// "a" + "b" -> one string, so 'child_' + 'process' is seen as child_process
function joinConcat(code, strs) {
  const orig = strs.length; let prev;
  do { prev = code; code = code.replace(/"(\d+)"\s*\+\s*"(\d+)"/g, (_, a, b) => { strs.push(strs[a] + strs[b]); return `"${strs.length - 1}"`; }); } while (code !== prev);
  return { code, orig };
}
const BAD_WORD = /^(?:child_process|eval$|Function$|powershell(?:\.exe)?|cmd(?:\.exe)?$|\/bin\/(?:ba)?sh|net\s+user|certutil|bitsadmin|mshta|wscript|cscript|rundll32|regsvr32|nc\s+-e|\/dev\/tcp|\.ssh|id_rsa|Login Data|wallet\.dat|process\.binding|__import__|os\.system|subprocess)/i;
function structure(rel, src) {
  const py = PY.test(rel), out = [], sp = split(src, py), { code, orig } = joinConcat(sp.code, sp.strs), strs = sp.strs;
  const add = (re, id, score, why, fam = 'Dynamic Code') => { let m, k = 0; re.lastIndex = 0; while ((m = re.exec(code)) && k++ < 3) out.push(F(rel, lineOf(sp.code, Math.min(sp.code.length, m.index)), id, fam, score, m[0].replace(/\s+/g, ' '), why)); };
  // a string ASSEMBLED from pieces that names something dangerous
  strs.forEach((s, i) => { if (i >= orig && BAD_WORD.test(s.trim())) out.push(F(rel, 0, 'S1', 'Obfuscation', 0.85, `"${s.slice(0, 40)}" built from pieces`, 'A dangerous word is never written whole; it is glued together at run time so a text search cannot see it')); });
  // a dangerous word written as \x / \u escape codes
  const escs = src.match(/["'`][^"'`\n]{0,200}["'`]/g) || [];
  for (const r of escs) if (/\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/i.test(r) && BAD_WORD.test(unesc(r.slice(1, -1)).trim())) { out.push(F(rel, 0, 'S2', 'Obfuscation', 0.85, `"${unesc(r.slice(1, -1)).slice(0, 40)}" hidden as escape codes`, 'A dangerous word is written as \\x/\\u codes so a text search cannot see it')); break; }
  const decode = py ? /\b(?:b64decode|b32decode|a85decode|unhexlify|marshal\.loads|zlib\.decompress|codecs\.decode|fromhex)\b/ : /\b(?:atob|fromCharCode|unescape|inflateSync|gunzipSync)\b|Buffer\s*\.\s*from\s*\([^)]*"\d+"\s*\)|\.toString\(\s*"\d+"\s*\)/;
  const runs = py ? /\b(?:exec|eval|compile)\s*\(|\b__import__\s*\(|\bos\.system\b|\bos\.popen\b|\bsubprocess\.\w+\s*\(/ : /\beval\s*\(|\bnew\s+Function\b|\bvm\.\w+\s*\(|\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(/;
  const near = (() => { const dg = new RegExp(decode.source, 'g'); let m; while ((m = dg.exec(code))) { const w = code.slice(Math.max(0, m.index - 300), m.index + 300); if (runs.test(w)) return true; } return false; })();
  if (near) out.push(F(rel, 0, 'S3', 'Remote Execution', 0.9, 'decodes data and runs code within a few lines of each other', 'Decode-then-run is how a payload is hidden from readers; legitimate skills almost never need it'));
  const NL = '(?!"\\d+"\\s*[,)])'; // not a plain string literal
  if (py) {
    add(new RegExp(`\\b(?:exec|eval)\\s*\\(\\s*${NL}`, 'g'), 'S4', 0.65, 'Runs text as code: what it runs is not visible in the file');
    add(new RegExp(`\\b__import__\\s*\\(\\s*${NL}`, 'g'), 'S5', 0.7, 'Imports a module chosen at run time');
    add(/\bgetattr\s*\(\s*(?:__builtins__|builtins|os|sys|subprocess)\b/g, 'S6', 0.8, 'Reaches a dangerous function by a computed name');
    add(/\b(?:pickle|marshal|dill|cloudpickle)\.loads?\s*\(/g, 'S7', 0.6, 'Loading pickled data can run code');
    add(/\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True/g, 'S8', 0.55, 'Shell command line built from text', 'Command Execution');
  } else {
    add(new RegExp(`\\beval\\s*\\(\\s*${NL}`, 'g'), 'S4', 0.65, 'Runs text as code: what it runs is not visible in the file');
    add(/\bnew\s+Function\s*\(/g, 'S4', 0.65, 'Builds a function from text at run time');
    add(new RegExp(`\\brequire\\s*\\(\\s*${NL}[^)\\s]`, 'g'), 'S5', 0.7, 'Loads a module chosen at run time');
    add(new RegExp(`\\bimport\\s*\\(\\s*${NL}[^)\\s]`, 'g'), 'S5', 0.7, 'Imports a module chosen at run time');
    add(/\[\s*(?:"\d+"\s*\+|[A-Za-z_$][\w$]*\s*\+\s*")[^\]]*\]\s*\(/g, 'S6', 0.8, 'Calls a function whose name is computed');
    add(/\b(?:const|let|var)\s+\w+\s*=\s*(?:eval|require|process\.binding|Function)\s*[;\n,]/g, 'S9', 0.75, 'Aliases a dangerous function under another name to hide the call');
    add(/\bprocess\.(?:binding|dlopen)\s*\(/g, 'S10', 0.8, 'Reaches the runtime internals');
    add(new RegExp(`\\b(?:exec|execSync)\\s*\\(\\s*${NL}[^)]`, 'g'), 'S8', 0.5, 'Runs a command built at run time', 'Command Execution');
  }
  return out;
}

// ---------------- 2. yara-lite ----------------
let YARA = null;
function yaraRules() { if (!YARA) { try { YARA = JSON.parse(readFileSync(join(HERE, 'yara-lite-rules.json'), 'utf8')).rules.map(r => ({ ...r, rx: r.strings.map(s => new RegExp(s, 'i')) })); } catch { YARA = []; } } return YARA; }
function yaraLite(rel, text) {
  const out = [];
  for (const r of yaraRules()) {
    const hit = r.rx.filter(x => x.test(text)).length, need = r.condition === 'all' ? r.rx.length : r.condition === 'any' ? 1 : +r.condition;
    if (hit >= need) out.push(F(rel, 0, r.id, r.fam, r.score, `${r.name} (${hit}/${r.rx.length} signatures)`, r.why));
  }
  return out;
}
export function realYara(root, rulesFile) {
  const w = spawnSync('yara', ['-r', rulesFile, root], { encoding: 'utf8', timeout: 120000, shell: process.platform === 'win32' });
  if (w.error || w.status === null || w.status > 1) return { ran: false, findings: [] };
  const fs = [];
  for (const ln of (w.stdout || '').split('\n')) { const m = ln.trim().match(/^([\w.-]+)\s+(.+)$/); if (m) fs.push(F(m[2].replace(root, '').replace(/^[\\/]/, '').replace(/\\/g, '/'), 0, 'Y-' + m[1], 'YARA', 0.85, 'YARA rule ' + m[1], 'Matched by a rule you supplied')); }
  return { ran: true, findings: fs };
}

// ---------------- 3. dependencies ----------------
const TOP_NPM = 'react react-dom lodash express axios chalk commander debug moment request async underscore bluebird webpack typescript eslint prettier jquery vue next dotenv uuid yargs minimist glob rimraf semver tslib mkdirp inquirer colors cors mongoose mysql redis jest mocha jsonwebtoken bcrypt body-parser cross-env node-fetch zod rxjs puppeteer playwright electron passport nodemailer sharp cheerio openai discord.js telegraf crypto-js fs-extra execa chokidar'.split(' ');
const TOP_PY = 'requests numpy pandas urllib3 setuptools boto3 botocore certifi idna charset-normalizer python-dateutil pyyaml cryptography jinja2 flask django scipy pillow matplotlib pytest click colorama tqdm beautifulsoup4 lxml sqlalchemy psycopg2 aiohttp fastapi uvicorn pydantic openai anthropic selenium paramiko pycryptodome tensorflow torch scikit-learn opencv-python httpx rich typer pygments packaging wheel attrs'.split(' ');
const lev = (a, b) => { const d = Array.from({ length: a.length + 1 }, (_, i) => { const r = Array(b.length + 1).fill(0); r[0] = i; return r; }); for (let j = 1; j <= b.length; j++) d[0][j] = j; for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) { d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1); } return d[a.length][b.length]; };
const norm = n => n.toLowerCase().replace(/[_.]+/g, '-');
function typo(name, list) { const n = norm(name); if (list.includes(n) || n.length < 5) return null; for (const t of list) if (t.length >= 5 && lev(n, t) <= (t.length >= 9 ? 2 : 1)) return t; return null; }
export function parseDeps(rel, text) {
  const deps = [], findings = [], b = basename(rel).toLowerCase();
  if (b === 'package.json') {
    let pj; try { pj = JSON.parse(text); } catch { return { deps, findings }; }
    for (const k of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) for (const [n, v] of Object.entries(pj[k] || {})) deps.push({ eco: 'npm', name: n, spec: String(v), file: rel, ver: /^[~^]?(\d+\.\d+\.\d+)$/.exec(String(v))?.[1] || null });
    for (const [k, v] of Object.entries(pj.overrides || pj.resolutions || {})) if (typeof v === 'string' && /^(?:https?:|git|github:|file:)/.test(v)) findings.push(F(rel, 0, 'D6', 'Dependency', 0.7, `${k} -> ${v}`, 'An override forces a package from an outside address'));
  } else if (/^requirements.*\.txt$/.test(b)) {
    text.split(/\r?\n/).forEach((ln, i) => {
      const l = ln.replace(/\s#.*$/, '').trim(); if (!l || l.startsWith('#')) return;
      if (/^(?:--extra-index-url|--index-url|-i|--find-links|-f|--trusted-host)\b/.test(l)) { findings.push(F(rel, i + 1, 'D5', 'Dependency', /extra-index|trusted-host|find-links|^-f\b/.test(l) ? 0.8 : 0.5, l, 'A second package source lets an attacker publish a same-named package that wins ("dependency confusion")')); return; }
      if (/^(?:-e\s+)?(?:git\+|https?:|file:|\.\/|\/)/.test(l)) { findings.push(F(rel, i + 1, 'D3', 'Dependency', 0.7, l, 'Installed from an address, not from the checked package index: its content can change at any time')); return; }
      const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(==|>=|~=|<=|>|<|!=)?\s*([\w.*+!-]+)?/.exec(l); if (m) deps.push({ eco: 'PyPI', name: m[1], spec: (m[2] || '') + (m[3] || ''), file: rel, line: i + 1, ver: m[2] === '==' && /^\d/.test(m[3] || '') ? m[3] : null });
    });
  }
  for (const d of deps) {
    const t = typo(d.name, d.eco === 'npm' ? TOP_NPM : TOP_PY);
    if (t) findings.push(F(d.file, d.line || 0, 'D2', 'Dependency', 0.85, `${d.name} looks like ${t}`, 'A name one or two letters away from a famous package is the usual typosquatting trap'));
    if (d.eco === 'npm' && /^(?:https?:|git[+:@]|github:|file:|[\w-]+\/[\w.-]+$)/.test(d.spec)) findings.push(F(d.file, 0, 'D3', 'Dependency', 0.7, `${d.name}: ${d.spec}`, 'Installed from an address, not from the checked package index: its content can change at any time'));
    if (d.eco === 'npm' && /^(?:\*|latest|x|)$/.test(d.spec)) findings.push(F(d.file, 0, 'D4', 'Dependency', 0.4, `${d.name}: ${d.spec || '(any)'}`, 'Any version is accepted, so a later poisoned release is installed automatically'));
  }
  return { deps, findings };
}
export async function osvCheck(deps) {
  const q = deps.filter(d => d.ver); if (!q.length) return { ran: true, asked: 0, findings: [] };
  try {
    const r = await fetch('https://api.osv.dev/v1/querybatch', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ queries: q.map(d => ({ package: { name: d.name, ecosystem: d.eco }, version: d.ver })) }), signal: AbortSignal.timeout(20000) });
    if (!r.ok) return { ran: false, asked: q.length, findings: [], error: 'HTTP ' + r.status };
    const j = await r.json(), fs = [];
    (j.results || []).forEach((x, i) => { const v = x.vulns || []; if (v.length) { const d = q[i]; fs.push(F(d.file, d.line || 0, 'D1', 'Dependency', v.length > 2 ? 0.7 : 0.6, `${d.name}@${d.ver}: ${v.slice(0, 3).map(z => z.id).join(', ')}${v.length > 3 ? ' +' + (v.length - 3) : ''}`, 'Known vulnerability in this exact version (OSV.dev). Check the advisory; upgrading is usually the fix')); } });
    return { ran: true, asked: q.length, findings: fs };
  } catch (e) { return { ran: false, asked: q.length, findings: [], error: e.name || 'error' }; }
}

// ---------------- entry point used by skillscan.mjs ----------------
export function deepFile(rel, text, isCode) {
  const out = [];
  if (isCode && (JS.test(rel) || PY.test(rel))) out.push(...structure(rel, text));
  if (isCode) out.push(...yaraLite(rel, text));
  return out;
}
