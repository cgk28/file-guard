#!/usr/bin/env node
// file-guard signer: holds the signing key where the agent's own Windows account cannot read it, and signs a new
// baseline ONLY after a one-time code, sent to the owner's phone, comes back. Zero dependencies, Node 18+.
// Runs as SYSTEM from a scheduled task (see install-signer.ps1). Commands:
//   serve   [--dir D] [--test-notify FILE]   poll the inbox forever
//   keygen  [--dir D] [--force 1]             make the key pair + pin (installer only)
//   status  [--dir D]
// Protocol (all files in <dir>): inbox/<id>.req.json {id,reason,data}  ->  Telegram message with a 6-digit code
//   inbox/<id>.code {code}  ->  outbox/<id>.sig (Ed25519 over the exact bytes of `data`) or outbox/<id>.err
import { createHash, generateKeyPairSync, createPrivateKey, sign, randomBytes, randomInt } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, unlinkSync, appendFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { execFile } from 'node:child_process';

const [cmd, ...rest] = process.argv.slice(2), A = {};
for (let i = 0; i < rest.length; i += 2) A[rest[i].replace(/^--/, '')] = rest[i + 1];
const DIR = A.dir || join(process.env.ProgramData || 'C:\\ProgramData', 'FileGuard', 'signer');
const F = { key: join(DIR, 'key.pem'), pub: join(DIR, 'public.pem'), pin: join(DIR, 'pin.txt'), last: join(DIR, 'last.json'), notify: join(DIR, 'notify.json'), log: join(DIR, 'log.txt'), hb: join(DIR, 'heartbeat.txt'), ready: join(DIR, 'ready.flag'), inbox: join(DIR, 'inbox'), outbox: join(DIR, 'outbox'), state: join(DIR, 'state') };
const sha = b => createHash('sha256').update(b).digest('hex');
const log = m => { try { appendFileSync(F.log, new Date().toISOString() + ' ' + m + '\n'); } catch {} }; // never log codes or tokens
const TTL = 3 * 60 * 1000, MAXTRY = 3, MAXREQ = 5, MINGAP = A.mingap ? +A.mingap : 20 * 1000, MAXBYTES = 4 * 1024 * 1024; // --mingap only for tests: the SYSTEM task is started without arguments

if (cmd === 'keygen') {
  if (existsSync(F.key) && A.force !== '1') { console.error('REFUSED: a signer key already exists (use --force 1 to replace it).'); process.exit(1); }
  for (const d of [DIR, F.inbox, F.outbox, F.state]) mkdirSync(d, { recursive: true });
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  writeFileSync(F.key, privateKey.export({ type: 'pkcs8', format: 'pem' })); writeFileSync(F.pub, pem); writeFileSync(F.pin, sha(pem).slice(0, 16));
  console.log('OK key pair created. Fingerprint ' + sha(pem).slice(0, 16)); process.exit(0);
}
if (cmd === 'status') { console.log(JSON.stringify({ dir: DIR, key: existsSync(F.key), ready: existsSync(F.ready), heartbeat: existsSync(F.hb) ? readFileSync(F.hb, 'utf8').trim() : null, pin: existsSync(F.pin) ? readFileSync(F.pin, 'utf8').trim() : null })); process.exit(0); }
if (cmd !== 'serve') { console.log('Usage: signer.mjs <serve|keygen|status> [--dir D] [--test-notify FILE]'); process.exit(2); }
if (!existsSync(F.key)) { console.error('No key. Run keygen first.'); process.exit(1); }
const priv = createPrivateKey(readFileSync(F.key, 'utf8'));
for (const d of [F.inbox, F.outbox, F.state]) mkdirSync(d, { recursive: true });

// ---- what will be signed, described by the signer itself (never by the requester) ----
function flat(d) { const o = {}; for (const k of ['locked', 'append', 'watch']) for (const [p, v] of Object.entries(d[k] || {})) o[p] = JSON.stringify(v); return o; }
function describe(dataStr) {
  let d; try { d = JSON.parse(dataStr); } catch { return null; }
  if (!d || typeof d !== 'object' || !d.locked || !d.watch || !d.cfg) return null;
  let prev = null; try { prev = JSON.parse(readFileSync(F.last, 'utf8')); } catch {}
  const n = flat(d), o = prev ? flat(prev) : {}, add = [], chg = [], rem = [];
  for (const p of Object.keys(n)) { if (!(p in o)) add.push(p); else if (o[p] !== n[p]) chg.push(p); }
  for (const p of Object.keys(o)) if (!(p in n)) rem.push(p);
  const cfgChanged = prev ? JSON.stringify(prev.cfg) !== JSON.stringify(d.cfg) : false;
  const show = (t, a) => a.length ? `${t} ${a.length}: ` + a.slice(0, 8).join(', ') + (a.length > 8 ? ` (+${a.length - 8} more)` : '') : '';
  const lines = prev ? [show('NEW', add), show('CHANGED', chg), show('REMOVED', rem), cfgChanged ? 'SETTINGS CHANGED (watch list / notify / extra paths)' : ''].filter(Boolean) : [`FIRST baseline: ${Object.keys(n).length} files`];
  if (prev && !lines.length) lines.push('no file differences from the last signed baseline');
  return { text: lines.join('\n'), hash: sha(dataStr).slice(0, 8) };
}

// ---- notify the owner (Telegram), or a file in tests ----
async function send(text) {
  if (A['test-notify']) { appendFileSync(A['test-notify'], text + '\n---\n'); return true; }
  try {
    const n = JSON.parse(readFileSync(F.notify, 'utf8'));
    const r = await fetch(`https://api.telegram.org/bot${n.token}/sendMessage`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ chat_id: n.chat, text: '[file-guard signer] ' + text }), signal: AbortSignal.timeout(15000) });
    if (!r.ok) { log('telegram HTTP ' + r.status); return false; } return true;
  } catch (e) { log('telegram failed: ' + (e.name || 'error')); return false; }
}

// Code shown ON THIS PC (msg.exe to every logged-in session): Telegram never sees it, so whoever controls Telegram cannot approve.
function localCode(text) {
  if (A['test-local']) { appendFileSync(A['test-local'], text + '\n---\n'); return Promise.resolve(true); }
  return new Promise(res => execFile(join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'msg.exe'), ['*', '/TIME:600', text], { timeout: 15000 }, e => { if (e) log('msg.exe failed: ' + (e.code || 'error')); res(!e); }));
}
let LOCAL = true; try { LOCAL = JSON.parse(readFileSync(F.notify, 'utf8')).local !== false; } catch {}
const okId = id => /^[a-f0-9]{16,32}$/.test(id);
const sf = id => join(F.state, id + '.json');
const out = (id, ext, body) => writeFileSync(join(F.outbox, id + '.' + ext), body);
let lastReq = 0;
async function tick() {
  writeFileSync(F.hb, new Date().toISOString());
  const now = Date.now(); let files = [];
  try { files = readdirSync(F.inbox); } catch {}
  const states = readdirSync(F.state).filter(f => f.endsWith('.json'));
  for (const f of states) { try { const s = JSON.parse(readFileSync(join(F.state, f), 'utf8')); if (now > s.exp) { unlinkSync(join(F.state, f)); log('expired ' + s.id); } } catch {} }
  // 1. new requests
  for (const f of files.filter(x => x.endsWith('.req.json'))) {
    const id = f.slice(0, -9); const p = join(F.inbox, f);
    try {
      if (!okId(id) || existsSync(sf(id))) { unlinkSync(p); continue; }
      if (statSync(p).size > MAXBYTES) { unlinkSync(p); log('too big ' + id); continue; }
      const r = JSON.parse(readFileSync(p, 'utf8')); unlinkSync(p);
      if (readdirSync(F.state).length >= MAXREQ || now - lastReq < MINGAP) { out(id, 'err', 'busy: try again in a minute'); log('rate limited ' + id); continue; }
      const d = describe(String(r.data)); if (!d) { out(id, 'err', 'bad request'); continue; }
      const code = String(randomInt(100000, 1000000)), salt = randomBytes(8).toString('hex');
      writeFileSync(sf(id), JSON.stringify({ id, h: sha(code + salt), salt, exp: now + TTL, tries: 0, data: String(r.data), hash: d.hash }));
      lastReq = now;
      const reason = String(r.reason || '').replace(/\s+/g, ' ').slice(0, 200);
      const body = `Request to re-sign the file-guard baseline.\nReason given: "${reason}"\n${d.text}\nData fingerprint: ${d.hash}\n`;
      let ok;
      if (LOCAL) { // fail closed: the code goes only to the screen of this PC, never to Telegram
        const shown = await localCode(`[file-guard] Approval code: ${code} (3 min, 3 tries). Reason: "${reason}". ${d.text.replace(/\n/g, ' | ')}`);
        if (!shown) { unlinkSync(sf(id)); out(id, 'err', 'could not show the code on this PC (msg.exe missing?); nothing signed'); continue; }
        ok = await send(body + 'Approval code: shown on the PC screen (not sent here). Give it to the agent ONLY if you asked for exactly this.');
      } else ok = await send(body + `Approval code: ${code} (3 min, 3 tries). Give it to the agent ONLY if you asked for exactly this.`);
      if (!ok) { unlinkSync(sf(id)); out(id, 'err', 'could not reach the owner (Telegram); nothing signed'); }
      else log('request ' + id + ' sent (' + d.hash + ')');
    } catch (e) { log('bad request file ' + f + ': ' + e.message); try { unlinkSync(p); } catch {} }
  }
  // 2. codes
  for (const f of files.filter(x => x.endsWith('.code'))) {
    const id = f.slice(0, -5), p = join(F.inbox, f);
    try {
      const raw = readFileSync(p, 'utf8'); unlinkSync(p);
      if (!okId(id) || !existsSync(sf(id))) continue;
      const s = JSON.parse(readFileSync(sf(id), 'utf8')), code = String(JSON.parse(raw).code || '').trim();
      if (now > s.exp) { unlinkSync(sf(id)); out(id, 'err', 'expired'); continue; }
      if (sha(code + s.salt) === s.h) {
        const sig = sign(null, Buffer.from(s.data), priv).toString('base64');
        writeFileSync(F.last, s.data); out(id, 'sig', sig); unlinkSync(sf(id)); log('signed ' + id + ' (' + s.hash + ')');
        await send(`Baseline signed (fingerprint ${s.hash}).`);
      } else {
        s.tries++; log('wrong code for ' + id + ' (' + s.tries + ')');
        if (s.tries >= MAXTRY) { unlinkSync(sf(id)); out(id, 'err', 'too many wrong codes; request cancelled'); await send('A request was cancelled after 3 wrong codes. If this was not you, something on this PC is guessing codes.'); }
        else writeFileSync(sf(id), JSON.stringify(s));
      }
    } catch (e) { log('bad code file ' + f + ': ' + e.message); try { unlinkSync(p); } catch {} }
  }
}
log('signer started');
for (;;) { try { await tick(); } catch (e) { log('tick error: ' + e.message); } await new Promise(r => setTimeout(r, 1500)); }
