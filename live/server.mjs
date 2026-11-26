// TrustMe live window: tiny local server (127.0.0.1 only) that serves the terminal page + the plugin feed.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const dir = path.dirname(fileURLToPath(import.meta.url));
const store = path.join(os.homedir(), 'aicoworker', 'aicwgw', 'plugins-data', 'file-guard-wall', 'store.json');
import { secretsTool, stringsBin } from '../tools/scanbin.mjs';
let tools = null; // scanner availability, re-checked every 60 s
const PORT = 7077;
http.createServer((req, res) => {
  if (req.url.startsWith('/feed')) {
    let out = { lines: [], blocked: 0 };
    try { const j = JSON.parse(fs.readFileSync(store, 'utf8')); out = { lines: (j.term || []).filter((x) => x.tool).slice(-40), blocked: j.blocked || 0 }; } catch {}
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    return res.end(JSON.stringify(out));
  }
  if (req.url.startsWith('/status')) {
    const o = { watch: watchLog.length, dirty: watchLog.filter((x) => x.verdict === 'dirty').length, mode: 'normal', attacks: null, benign: null, audit: 0, denied: 0, scannedOk: 0 };
    try {
      const md = fs.readFileSync(path.join(dir, '..', 'REDTEAM.md'), 'utf8');
      const sec = md.split(/^## Mode /m).find((x) => x.startsWith('normal')) || '';
      const a = sec.match(/Attacks blocked: \*\*(\d+)\/(\d+)/), b = sec.match(/Benign passed: \*\*(\d+)\/(\d+)/);
      if (a) o.attacks = a[1] + '/' + a[2]; if (b) o.benign = b[1] + '/' + b[2];
    } catch {}
    try {
      let lines;
      try { lines = fs.readFileSync(path.join(os.homedir(), '.trustme', 'audit.jsonl'), 'utf8').trim().split('\n').slice(-500); }
      catch { lines = (JSON.parse(fs.readFileSync(store, 'utf8')).audit || []).map((r) => JSON.stringify(r)); }
      const day = Date.now() - 86400000;
      for (const l of lines) { try { const r = JSON.parse(l); if (Date.parse(r.t) < day) continue; o.audit++; if (r.mode) o.mode = r.mode; if (r.verdict === 'deny') o.denied++; if (r.verdict === 'allow') o.scannedOk++; } catch {} }
    } catch {}
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    return res.end(JSON.stringify(o));
  }
  if (req.url.startsWith('/scanners')) {
    const sf = path.join(path.dirname(store), 'extscan-stats.json'); let o = { scans: 0, findings: 0, flagged: 0 };
    try { o = JSON.parse(fs.readFileSync(sf, 'utf8')); } catch {}
    if (!tools || Date.now() - tools.at > 60000) { const s = secretsTool(); tools = { at: Date.now(), secretsTool: s ? s.name : 'trufflehog', secretsOk: !!s, strings: !!stringsBin() }; }
    o.secretsTool = tools.secretsTool; o.secretsOk = tools.secretsOk; o.strings = tools.strings;
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    return res.end(JSON.stringify(o));
  }
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(fs.readFileSync(path.join(dir, 'index.html')));
}).listen(PORT, '127.0.0.1', () => console.log('TrustMe live on http://127.0.0.1:' + PORT));

// Telegram alert when the wall blocks something new (message only, no secrets).
import { execFile } from 'node:child_process';
let seen = -1;
setInterval(() => {
  try {
    const j = JSON.parse(fs.readFileSync(store, 'utf8'));
    const n = j.blocked || 0;
    if (seen >= 0 && n > seen && fs.existsSync(path.join(dir, 'notify.ps1'))) {
      const msg = '⛔ TrustMe chặn ' + (n - seen) + ' hành động:\n' + (j.last || []).slice(-(n - seen)).join('\n');
      execFile('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.join(dir, 'notify.ps1')], { env: { ...process.env, TM_MSG: msg }, windowsHide: true }, () => {});
    }
    seen = n;
  } catch {}
}, 5000);

// ---- WATCH: executable files that appear or change while untrusted content is in play (the plugin cannot see child processes) ----
const WS = path.join(os.homedir(), 'aicoworker', 'aicwgw', 'workspace-main');
const RULES = (() => { try { const r = JSON.parse(fs.readFileSync(path.join(dir, '..', 'plugin', 'rules.json'), 'utf8')); const c = (a) => a.map((x) => new RegExp(x.p, x.f || '')); return { all: [...r.dangerous, ...r.taintSensitive, ...r.contentExtra].map((x) => ({ re: new RegExp(x.p, x.f || ''), why: x.why })), ext: new RegExp('\\.(' + r.executableExt.join('|') + ')$', 'i') }; } catch { return null; } })();
const fseen = new Map();
const watchLog = [];
let watchBase = false;
function walk(d, out, depth) {
  if (depth > 6) return;
  let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
  for (const e of ents) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p, out, depth + 1); else if (RULES && RULES.ext.test(e.name)) out.push(p);
  }
}
function notify(msg) {
  if (!fs.existsSync(path.join(dir, 'notify.ps1'))) return;
  execFile('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.join(dir, 'notify.ps1')], { env: { ...process.env, TM_MSG: msg }, windowsHide: true }, () => {});
}
setInterval(() => {
  if (!RULES) return;
  let j = {}; try { j = JSON.parse(fs.readFileSync(store, 'utf8')); } catch {}
  const tainted = Object.entries(j).some(([k, v]) => k.startsWith('taint:') && v);
  const files = []; walk(WS, files, 0);
  for (const f of files) {
    let m; try { m = fs.statSync(f).mtimeMs; } catch { continue; }
    const old = fseen.get(f); fseen.set(f, m);
    if (!watchBase || old === m || !tainted) continue;
    let body = ''; try { body = fs.readFileSync(f, 'utf8').slice(0, 1000000).toLowerCase().replace(/\s+/g, ' '); } catch {}
    const bad = RULES.all.find((r) => r.re.test(body));
    const rec = { t: new Date().toISOString(), file: path.basename(f), verdict: bad ? 'dirty' : 'clean', why: bad ? bad.why : '' };
    watchLog.push(rec); if (watchLog.length > 100) watchLog.shift();
    if (bad) notify('TrustMe: file "' + rec.file + '" written while untrusted content was in play contains: ' + rec.why);
  }
  watchBase = true;
}, 4000);
// alerts the plugin queued (late taint)
let alertsSeen = -1;
setInterval(() => {
  try {
    const al = JSON.parse(fs.readFileSync(store, 'utf8')).alerts || [];
    if (alertsSeen >= 0 && al.length > alertsSeen) for (const a of al.slice(alertsSeen)) notify('TrustMe: ' + a.text);
    alertsSeen = al.length;
  } catch {}
}, 5000);
