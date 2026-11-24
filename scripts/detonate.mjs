#!/usr/bin/env node
// file-guard detonate: run a NEW or CHANGED script of a skill inside a throw-away, network-less container and report what it TRIES to do
// (read secrets, open sockets, spawn shells, write outside /tmp). Static scanners read text; this watches behaviour.
// Usage: node detonate.mjs <file|dir> [--image IMG] [--timeout 10] [--args "a b"]
// Needs podman or docker. Zero dependencies, Node 18+. Never runs on the host: if no container runtime is found it refuses.
import { mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, lstatSync, copyFileSync, rmSync, mkdtempSync } from 'node:fs';
import { join, resolve, extname, basename, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

const argv = process.argv.slice(2), target = argv[0];
const opt = n => { const i = argv.indexOf('--' + n); return i > 0 ? argv[i + 1] : undefined; };
if (!target) { console.log('Usage: detonate.mjs <script file | folder> [--image IMG] [--timeout 10] [--args "a b"]'); process.exit(2); }
const rt = ['podman', 'docker'].find(c => spawnSync(c, ['--version']).status === 0);
if (!rt) { console.log('REFUSED: no podman/docker found. Scripts are never executed on the host.'); process.exit(2); }
const image = opt('image') || 'localhost/openclaw-sandbox:bookworm-slim', secs = +(opt('timeout') || 10);
if (spawnSync(rt, ['image', 'exists', image]).status !== 0 && spawnSync(rt, ['image', 'inspect', image]).status !== 0) { console.log(`REFUSED: image ${image} not present (pass --image with one that has node/python3/bash).`); process.exit(2); }

const KINDS = { '.js': 'node', '.mjs': 'node', '.cjs': 'node', '.py': 'py', '.sh': 'sh', '.bash': 'sh' };
function files(p, out = []) { const st = lstatSync(p); if (st.isSymbolicLink()) return out; if (st.isDirectory()) { for (const n of readdirSync(p)) if (!['node_modules', '.git'].includes(n)) files(join(p, n), out); } else if (KINDS[extname(p).toLowerCase()] && st.size < 1e6) out.push(p); return out; }
const list = files(resolve(target)); if (!list.length) { console.log('Nothing to run (no .js/.mjs/.py/.sh files).'); process.exit(0); }

// --- hooks that log behaviour (mounted read-only into the container) ---
const RULES = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'detonate-rules.json'), 'utf8')), SENS = RULES.sens;
const NODE_HOOK = `const fs=require('fs'),cp=require('child_process'),net=require('net'),dns=require('dns'),L='/out/log.jsonl',re=new RegExp(${JSON.stringify(SENS)},'i');
const log=(k,d)=>{try{fs.appendFileSync(L,JSON.stringify({k,d:String(d).slice(0,200)})+'\\n')}catch{}};
for(const m of ['readFileSync','readFile','openSync','open','createReadStream','readdirSync','existsSync','statSync']){const o=fs[m];fs[m]=function(p,...a){if(typeof p==='string'&&re.test(p)&&!p.startsWith('/job'))log('read-sensitive',p);return o.call(this,p,...a)}}
for(const m of ['writeFileSync','writeFile','appendFileSync','createWriteStream','unlinkSync','rmSync']){const o=fs[m];fs[m]=function(p,...a){if(typeof p==='string'&&!p.startsWith('/tmp')&&!p.startsWith('/out'))log('write-outside-tmp',p);return o.call(this,p,...a)}}
for(const m of ['exec','execSync','spawn','spawnSync','execFile','execFileSync','fork']){const o=cp[m];cp[m]=function(c,...a){log('spawn',c+' '+(Array.isArray(a[0])?a[0].join(' '):''));return o.call(this,c,...a)}}
const oc=net.Socket.prototype.connect;net.Socket.prototype.connect=function(...a){log('network',JSON.stringify(a[0]&&a[0].host||a[0]));return oc.apply(this,a)};
const dl=dns.lookup;dns.lookup=function(h,...a){log('network-dns',h);return dl.call(this,h,...a)};
if(typeof fetch==='function'){const f=fetch;globalThis.fetch=function(u,...a){log('network-fetch',u&&u.url||u);return f.call(this,u,...a)}}
process.env=new Proxy(process.env,{get(t,k){if(typeof k==='string'&&/key|token|secret|pass/i.test(k))log('read-env',k);return t[k]}});
const ev=global.eval;global.eval=function(s){log('eval',s);return ev(s)};`;
const PY_HOOK = `import sys,json,re
L='/out/log.jsonl';R=re.compile(${JSON.stringify(SENS).replace(/\\\\/g, '\\\\')},re.I)
def log(k,d):
    try: open(L,'a').write(json.dumps({'k':k,'d':str(d)[:200]})+'\\n')
    except Exception: pass
def h(ev,a):
    if ev=='open' and isinstance(a[0],str):
        if R.search(a[0]) and not a[0].startswith('/job'): log('read-sensitive',a[0])
        elif len(a)>1 and isinstance(a[1],str) and any(c in a[1] for c in 'wax+') and not a[0].startswith(('/tmp','/out','/dev')): log('write-outside-tmp',a[0])
    elif ev=='socket.connect': log('network',a[1])
    elif ev=='socket.getaddrinfo': log('network-dns',a[0])
    elif ev in('subprocess.Popen','os.system','os.exec','os.spawn'): log('spawn',a[:2])
sys.addaudithook(h)`;
const SH_SHIMS = ['curl', 'wget', 'nc', 'ncat', 'ssh', 'scp', 'ftp', 'telnet', 'sudo', 'crontab', 'at'];

const work = mkdtempSync(join(tmpdir(), 'fg-det-')); let worst = 0; const rows = [];
for (const f of list) {
  const kind = KINDS[extname(f).toLowerCase()], job = join(work, 'job'), out = join(work, 'out'), hooks = join(work, 'hooks'), home = join(work, 'home');
  for (const d of [job, out, hooks, home]) { rmSync(d, { recursive: true, force: true }); mkdirSync(d, { recursive: true }); }
  copyFileSync(f, join(job, basename(f)));
  // decoy files: if the script reads or sends these, it is stealing (they are fake, see detonate-rules.json)
  for (const d of RULES.decoys) { mkdirSync(dirname(join(home, d.path)), { recursive: true }); writeFileSync(join(home, d.path), d.text); }

  writeFileSync(join(hooks, 'hook.js'), NODE_HOOK); mkdirSync(join(hooks, 'py'), { recursive: true }); writeFileSync(join(hooks, 'py', 'sitecustomize.py'), PY_HOOK);
  mkdirSync(join(hooks, 'bin'), { recursive: true });
  for (const c of SH_SHIMS) writeFileSync(join(hooks, 'bin', c), `#!/bin/sh\nprintf '{"k":"network-tool","d":"%s"}\\n' "${c} $(echo "$*" | tr -d '"\\\\')" >> /out/log.jsonl\nexit 1\n`, { mode: 0o755 });
  const cmd = kind === 'node' ? ['node', '--require', '/hooks/hook.js', '/job/' + basename(f)] : kind === 'py' ? ['python3', '/job/' + basename(f)] : ['bash', '-x', '/job/' + basename(f)];
  const extra = (opt('args') || '').split(' ').filter(Boolean);
  const r = spawnSync(rt, ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'all', '--user', '65534:65534', '--security-opt', 'no-new-privileges', '--pids-limit', '64', '--memory', '256m',
    '--tmpfs', '/tmp:rw,size=16m', '-v', `${job}:/job:ro`, '-v', `${hooks}:/hooks:ro`, '-v', `${home}:/home/sandbox:rw`, '-v', `${out}:/out:rw`,
    '-e', 'HOME=/home/sandbox', '-e', 'PYTHONPATH=/hooks/py', '-e', 'PATH=/hooks/bin:/usr/local/bin:/usr/bin:/bin', ...Object.entries(RULES.env).flatMap(([k, v]) => ['-e', k + '=' + v]),
    '--stop-timeout', '1', image, 'timeout', String(secs), ...cmd, ...extra], { encoding: 'utf8', timeout: (secs + 60) * 1000 });
  const ev = existsSync(join(out, 'log.jsonl')) ? readFileSync(join(out, 'log.jsonl'), 'utf8').split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean) : [];
  if (kind === 'sh') for (const l of (r.stderr || '').split('\n')) { if (/^\++ /.test(l)) { const c = l.replace(/^\++ /, ''); if (new RegExp(SENS, 'i').test(c) && /\b(cat|cp|tar|zip|base64|grep|less|head)\b/.test(c)) ev.push({ k: 'read-sensitive', d: c }); if (/^(curl|wget|nc|ncat|ssh|scp|ftp|telnet)\b|\| *(curl|wget|nc) /.test(c) && !ev.some(e => e.k === 'network-tool')) ev.push({ k: 'network-tool', d: c }); if (/\b(eval|base64 -d|bash -c|sh -c|chmod \+x)\b/.test(c)) ev.push({ k: 'eval', d: c }); } }
  const all = (r.stdout || '') + (r.stderr || ''), leaked = all.match(/FG-CANARY-\d{4}/g);
  if (leaked) ev.push({ k: 'canary-printed', d: [...new Set(leaked)].join(',') });
  const W = { 'read-sensitive': 3, 'canary-printed': 3, network: 3, 'network-fetch': 3, 'network-tool': 3, 'network-dns': 2, spawn: 1, eval: 2, 'write-outside-tmp': 2, 'read-env': 2 };
  const kinds = [...new Set(ev.map(e => e.k))], score = kinds.reduce((s, k) => s + (W[k] || 1), 0);
  worst = Math.max(worst, score); rows.push({ f, kind, score, kinds, ev, code: r.status, ran: r.status !== 125 && r.status !== 126 });
  if (r.status === 125) rows.at(-1).note = 'container failed to start: ' + (r.stderr || '').slice(0, 160);
}
rmSync(work, { recursive: true, force: true });
for (const x of rows) {
  const verdict = x.note ? 'COULD NOT RUN' : x.score >= 3 ? 'HIGH RISK' : x.score >= 1 ? 'SUSPICIOUS' : 'no risky behaviour seen';
  console.log(`${verdict.padEnd(24)} ${x.f}  (${x.kind}, exit ${x.code})${x.kinds.length ? '  [' + x.kinds.join(', ') + ']' : ''}${x.note ? '  ' + x.note : ''}`);
  for (const e of x.ev.slice(0, 6)) console.log(`      ${e.k}: ${e.d}`);
}
console.log('\nNote: "no risky behaviour seen" only means nothing happened in this one run (no network, fake secrets, ' + secs + 's, default arguments). Code that waits for a date, an argument or a network reply stays hidden. It is evidence, not proof.');
process.exit(worst >= 3 ? 1 : 0);