// node tests/core.test.js <identityPubB64> <dir>
// Exercises core.js the way the page does, with PRF outputs simulated.
// Reads <dir>/requests.json ({label: tsr1 string}) issued by the Python side,
// writes deliveries and a vault blob back into <dir> for it to consume.
'use strict';
require('../site/core.js');
const fs = require('fs');
const path = require('path');
const C = globalThis.TAPSEAL;
const [vmKey, dir] = process.argv.slice(2);
const reqs = JSON.parse(fs.readFileSync(path.join(dir, 'requests.json'), 'utf8'));
let n = 0;
const ok = (cond, msg) => { if (!cond) { console.error('FAIL', msg); process.exit(1); } console.log(`js${++n} ${msg}: OK`); };
const rejects = async (p) => { try { await p; return false; } catch { return true; } };
const enc = (o) => C.b64e(new TextEncoder().encode(JSON.stringify(o)));
const dec = (s) => JSON.parse(Buffer.from(s, 'base64url'));
const write = (f, s) => fs.writeFileSync(path.join(dir, f), s);

(async () => {
  // keyring
  const K = C.rand(32), prfA = C.rand(32), prfB = C.rand(32), paper = C.rand(32);
  const slotA = await C.wrapK(K, prfA), slotB = await C.wrapK(K, prfB), paperSlot = await C.wrapK(K, paper);
  ok(C.b64e(await C.unwrapK(slotA, prfA)) === C.b64e(K) && C.b64e(await C.unwrapK(slotB, prfB)) === C.b64e(K),
    'both key slots unwrap the same vault key');
  ok(await rejects(C.unwrapK(slotA, prfB)), 'wrong PRF output cannot unwrap a slot');
  const printed = C.paperEncode(paper);
  ok(printed.replace(/-/g, '').length === 52, 'paper key is 52 base32 chars');
  ok(C.b64e(await C.unwrapK(paperSlot, C.paperDecode(printed.toLowerCase().replace(/-/g, ' ')))) === C.b64e(K),
    'paper key unwraps K, tolerant of case and separators');

  // vault
  const blob = await C.seal(K, { name: 'oura', kind: 'file', ttl: 3600, data: '{"session":"s3cret"}' });
  const v = await C.unseal(K, blob);
  ok(v.data === '{"session":"s3cret"}' && v.header.name === 'oura' && v.header.ttl === 3600, 'seal/unseal round trip');
  ok(await rejects(C.unseal(C.rand(32), blob)), 'other vault key cannot open a blob');
  const p = blob.split('.');
  ok(await rejects(C.unseal(K, ['tsv1', enc({ ...dec(p[1]), name: 'google-agent' }), p[2], p[3]].join('.'))),
    'renamed header fails authentication');
  ok(await rejects(C.unseal(K, ['tsv1', enc({ ...dec(p[1]), ttl: 86400 * 30 }), p[2], p[3]].join('.'))),
    'raised ttl in header fails authentication');
  const forged = await C.seal(C.rand(32), { name: 'oura', kind: 'file', ttl: 3600, data: 'attacker-token' });
  ok(await rejects(C.unseal(K, forged)), 'blob forged without K is rejected');
  write('vault.tsv', blob);

  // requests
  const req = await C.verifyRequest(vmKey, reqs.oura);
  ok(req.name === 'oura' && req.exp > C.now(), 'VM-signed request verifies against pinned identity');
  const rp = reqs.oura.split('.');
  ok(await rejects(C.verifyRequest(vmKey, ['tsr1', enc({ ...dec(rp[1]), name: 'other-secret' }), rp[2]].join('.'))),
    'request with altered name fails signature');
  ok(await rejects(C.verifyRequest(vmKey, ['tsr1', enc({ ...dec(rp[1]), epk: C.b64e(new Uint8Array([4, ...C.rand(64)])) }), rp[2]].join('.'))),
    'request with swapped key fails signature');
  ok(await rejects(C.verifyRequest(reqs.otherIdentity, reqs.oura)), 'request from a different VM is refused');
  ok(await rejects(C.verifyRequest(vmKey, reqs.oura, req.exp + 1)), 'expired request is refused');
  ok(await rejects(C.deliver(req, { name: 'other-secret', kind: 'file', exp: C.now() + 60, payload: 'x' })),
    'cannot deliver a different secret against a request');

  // google minting (fetch stubbed): refresh token must not appear in payload
  const gdata = JSON.stringify({ refresh_token: '1//LONG-LIVED', client_id: 'cid', client_secret: 'csec', scopes: ['s'] });
  const fakeFetch = async () => ({ ok: true, json: async () => ({ access_token: 'ya29.short', expires_in: 3599 }) });
  const g = await C.mintGoogle(gdata, 'google-auth', fakeFetch);
  ok(!g.payload.includes('LONG-LIVED') && JSON.parse(g.payload).token === 'ya29.short', 'google payload has access token only');
  const go = await C.mintGoogle(gdata, 'oauth2-go', fakeFetch);
  ok(JSON.parse(go.payload).access_token === 'ya29.short' && JSON.parse(go.payload).refresh_token === '', 'oauth2-go format');
  ok(await rejects(C.mintGoogle(gdata, 'google-auth', async () => { throw new TypeError('cors'); })),
    'CORS/network failure delivers nothing');

  // deliveries for the Python side
  const now = C.now();
  const r = async (label) => C.verifyRequest(vmKey, reqs[label]);
  const good = await C.deliver(req, { name: 'oura', kind: 'file', exp: now + 600, payload: v.data });
  write('good.tsd', good);
  write('wrapped.tsd', (await C.deliver(await r('wrapped'), { name: 'oura', kind: 'file', exp: now + 600, payload: v.data }))
    .replace(/(.{60})/g, '$1\n  '));
  write('expired.tsd', await C.deliver(await r('expired'), { name: 'oura', kind: 'file', exp: now - 5, payload: 'x' }));
  write('far.tsd', await C.deliver(await r('far'), { name: 'oura', kind: 'file', exp: now + 30 * 86400, payload: 'x' }));
  write('google.tsd', await C.deliver(await r('google'), { name: 'google-agent', kind: 'google', exp: g.exp, payload: g.payload }));
  const tamper = await C.deliver(await r('tamper'), { name: 'oura', kind: 'file', exp: now + 600, payload: 'x' });
  const tp = tamper.split('.');
  write('tampered.tsd', ['tsd1', enc({ ...dec(tp[1]), exp: now + 86400 }), tp[2], tp[3], tp[4]].join('.'));

  ok(await rejects(C.importIdentity(C.b64e(C.rand(65)))), 'malformed VM key rejected');
  console.log('fingerprint', await C.fingerprint(vmKey));
})().catch((e) => { console.error(e); process.exit(1); });
