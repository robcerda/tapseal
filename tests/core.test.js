// Page side of the interop tests, driven by tests/test_interop.py.
//   node tests/core.test.js setup <vmKey> <otherVmKey> <dir>
//       keyring, page key, rotation, and blob tests; writes state.json, cert files, blobs
//   node tests/core.test.js deliver <dir>
//       reads requests.json from the VM side; writes deliveries
// PRF outputs are simulated.
'use strict';
require('../site/core.js');
const fs = require('fs');
const path = require('path');
const C = globalThis.TAPSEAL;
const [mode, ...args] = process.argv.slice(2);
let n = 0;
const ok = (cond, msg) => { if (!cond) { console.error('FAIL', msg); process.exit(1); } console.log(`js${++n} ${msg}: OK`); };
const rejects = async (p) => { try { await p; return false; } catch { return true; } };
const enc = (o) => C.b64e(new TextEncoder().encode(JSON.stringify(o)));
const dec = (s) => JSON.parse(Buffer.from(s, 'base64url'));

async function setup(vmKey, otherVmKey, dir) {
  const write = (f, s) => fs.writeFileSync(path.join(dir, f), s);

  // keyring
  const K = C.rand(32), prfA = C.rand(32), prfB = C.rand(32), paper = C.rand(32);
  const slotA = await C.wrapK(K, prfA), slotB = await C.wrapK(K, prfB), paperSlot = await C.wrapK(K, paper);
  ok(C.b64e(await C.unwrapK(slotA, prfA)) === C.b64e(K) && C.b64e(await C.unwrapK(slotB, prfB)) === C.b64e(K),
    'both key slots unwrap the same vault key');
  ok(await rejects(C.unwrapK(slotA, prfB)), 'wrong PRF output cannot unwrap a slot');
  const printed = C.paperEncode(paper);
  ok(C.b64e(await C.unwrapK(paperSlot, C.paperDecode(printed.toLowerCase().replace(/-/g, ' ')))) === C.b64e(K),
    'paper key unwraps K, tolerant of case and separators');

  // config v2: padded wraps, trial unwrap, sealed metadata
  const wraps = [slotA, C.dummyWrap(), paperSlot, C.dummyWrap(), slotB];
  const hitB = await C.findWrap(wraps, prfB);
  ok(hitB && hitB.index === 4 && C.b64e(hitB.K) === C.b64e(K), 'trial unwrap finds the slot a secret opens');
  ok((await C.findWrap(wraps, C.rand(32))) === null, 'an unenrolled secret opens nothing');
  ok((await C.findWrap(wraps, paper)).index === 2, 'paper key found among padded wraps');
  const d = C.dummyWrap();
  ok(C.b64d(d.iv).length === C.b64d(slotA.iv).length && C.b64d(d.wrapped).length === C.b64d(slotA.wrapped).length,
    'dummy wraps have the same shape as real ones');
  const meta = await C.sealMeta(K, { slots: [{ label: 'bio', credId: 'x', synced: false, wrap: 4 }], paper: 2 });
  ok(!JSON.stringify(meta).includes('bio') && (await C.openMeta(K, meta)).slots[0].label === 'bio', 'labels are sealed under K');
  ok(await rejects(C.openMeta(C.rand(32), meta)), 'metadata does not open under another key');
  const meta3 = await C.sealMeta(K, { slots: [1, 2, 3].map((i) => ({ label: 'key number ' + i, credId: 'c'.repeat(86), synced: false, wrap: i })), paper: 0 });
  ok(meta.sealed.length === meta3.sealed.length, 'sealed metadata is padded: one slot and three slots look the same size');

  // page key
  const page = await C.newPageKey(K);
  const signer = await C.openPageKey(K, page.pageSeal);
  ok(signer.type === 'private' && !signer.extractable, 'page key opens under K, non extractable');
  ok(await rejects(C.openPageKey(C.rand(32), page.pageSeal)), 'page key does not open under another vault key');

  // vault
  const blob = await C.seal(K, { name: 'oura', kind: 'file', ttl: 3600, data: '{"session":"s3cret"}' });
  const gblob = await C.seal(K, { name: 'google-agent', kind: 'google', fmt: 'google-auth',
    data: JSON.stringify({ refresh_token: '1//LONG-LIVED', client_id: 'cid', client_secret: 'csec' }) });
  const v = await C.unseal(K, blob);
  ok(v.data === '{"session":"s3cret"}' && v.header.ttl === 3600, 'seal/unseal round trip');
  const p = blob.split('.');
  ok(await rejects(C.unseal(K, ['tsv1', enc({ ...dec(p[1]), name: 'google-agent' }), p[2], p[3]].join('.'))),
    'renamed header fails authentication');
  ok(await rejects(C.unseal(K, ['tsv1', enc({ ...dec(p[1]), ttl: 86400 * 30 }), p[2], p[3]].join('.'))),
    'raised ttl in header fails authentication');
  ok(await rejects(C.unseal(K, await C.seal(C.rand(32), { name: 'oura', kind: 'file', ttl: 3600, data: 'x' }))),
    'blob forged without K is rejected');

  // rotation: new K, re-sealed bundle; old factors open nothing new
  const K2 = C.rand(32);
  const stray = await C.seal(C.rand(32), { name: 'stray', kind: 'file', ttl: 3600, data: 'x' });
  const carried = await C.reseal(K, K2, C.makeBundle([blob, stray, gblob]));
  const rotated = carried.blobs;
  ok(rotated.length === 2 && carried.skipped.join() === 'stray', 'rotation skips blobs that do not open, and names them');
  const r0 = await C.unseal(K2, rotated[0]);
  ok(r0.data === v.data && r0.header.created === v.header.created && r0.header.ttl === 3600,
    'rotation re-seals blobs under the new vault key, headers kept');
  const oldFromPaper = await C.unwrapK(paperSlot, paper);
  ok(await rejects(C.unseal(oldFromPaper, rotated[0])) && await rejects(C.unseal(oldFromPaper, rotated[1])),
    'old paper key and old config cannot open re-sealed blobs');
  const page2 = await C.newPageKey(K2);
  ok(await rejects(C.openPageKey(K, page2.pageSeal)), 'old vault key cannot open the new page key');
  const signer2 = await C.openPageKey(K2, page2.pageSeal);

  // rotation handoff: signed by the OLD page key
  const handoff = await C.handoff(signer, page.pageKey, page2.pageKey, rotated);
  ok((await C.verifyHandoff(page.pageKey, handoff)).newPageKey === page2.pageKey, 'handoff verifies under the old page key');
  const forgedHandoff = await C.handoff(signer2, page.pageKey, page2.pageKey, rotated); // claims old key, signed by another
  ok(await rejects(C.verifyHandoff(page.pageKey, forgedHandoff)), 'handoff not signed by the old page key is refused');
  write('handoff.tsk', handoff);
  write('handoff_forged.tsk', forgedHandoff);
  write('state2.json', JSON.stringify({ K: C.b64e(K2), page: page2 }));

  // certificates
  const cert = await C.certify(signer, page.pageKey, vmKey, 30 * 86400);
  const ch = await C.verifyCert(page.pageKey, cert);
  ok(ch.vmKey === vmKey, 'certificate verifies against the page key');
  ok(await rejects(C.verifyCert(page2.pageKey, cert)), 'certificate from another page key is refused');
  const cp = cert.split('.');
  ok(await rejects(C.verifyCert(page.pageKey, ['tsc1', enc({ ...dec(cp[1]), vmKey: otherVmKey }), cp[2]].join('.'))),
    'certificate with a swapped VM key fails');
  ok(await rejects(C.verifyCert(page.pageKey, cert, ch.exp + 1)), 'expired certificate is refused');
  ok(await rejects(C.certify(signer, page.pageKey, vmKey, 31 * 86400)), 'certificate lifetime is capped at 30 days');
  ok(Number.isInteger(ch.iat), 'certificate carries iat');
  ok(await rejects(C.verifyCert(page.pageKey, cert, null, ch.iat + 1)), 'certificate issued before minCertIat is refused');
  ok((await C.verifyCert(page.pageKey, cert, null, ch.iat)).iat === ch.iat, 'certificate at minCertIat is accepted');
  // A 60 day certificate signed by the real page key: the VM must refuse it too.
  const t = C.now();
  const lh = enc({ v: 1, vmKey, pageKey: page.pageKey, iat: t, exp: t + 60 * 86400 });
  const lsig = C.b64e(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signer, new TextEncoder().encode('tsc1.' + lh)));
  write('cert_long.tsc', `tsc1.${lh}.${lsig}`);

  const otherPage = await C.newPageKey(C.rand(32));
  const foreign = await C.certify(signer, otherPage.pageKey, vmKey, 86400); // claims a page key it was not signed by

  write('state.json', JSON.stringify({ K: C.b64e(K), page }));
  write('cert.tsc', cert);
  write('cert_wrong_identity.tsc', await C.certify(signer, page.pageKey, otherVmKey, 86400));
  write('cert_foreign_page.tsc', foreign);
  write('vault.tsv', blob);
  write('google.tsv', gblob);
  console.log('fingerprint', await C.fingerprint(vmKey));
}

async function deliverAll(dir) {
  const read = (f) => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
  const write = (f, s) => fs.writeFileSync(path.join(dir, f), s);
  const st = read('state.json');
  const reqs = read('requests.json');
  const signer = await C.openPageKey(C.b64d(st.K), st.page.pageSeal);
  const cert = await C.verifyCert(st.page.pageKey, fs.readFileSync(path.join(dir, 'cert.tsc'), 'utf8'));
  const r = (label) => C.verifyRequest(cert.vmKey, reqs[label]);
  const now = C.now();

  const req = await r('good');
  ok(req.name === 'oura', 'VM signed request verifies against the certified identity');
  const rp = reqs.good.split('.');
  ok(await rejects(C.verifyRequest(cert.vmKey, ['tsr1', enc({ ...dec(rp[1]), name: 'monarch' }), rp[2]].join('.'))),
    'request with altered name fails signature');
  ok(await rejects(C.verifyRequest(reqs.otherVmKey, reqs.good)), 'request signed by an uncertified identity is refused');
  ok(await rejects(C.verifyRequest(cert.vmKey, reqs.good, req.exp + 1)), 'expired request is refused');
  ok(await rejects(C.verifyRequest(cert.vmKey, reqs.longlived)), 'request claiming a long lifetime is refused');
  ok(await rejects(C.deliver(req, signer, { name: 'monarch', kind: 'file', exp: now + 60, payload: 'x' })),
    'cannot deliver a different secret against a request');

  // google minting (fetch stubbed): refresh token must not appear in payload
  const gdata = JSON.stringify({ refresh_token: '1//LONG-LIVED', client_id: 'cid', client_secret: 'csec', scopes: ['s'] });
  const fakeFetch = async () => ({ ok: true, json: async () => ({ access_token: 'ya29.short', expires_in: 3599 }) });
  const g = await C.mintGoogle(gdata, 'google-auth', fakeFetch);
  ok(!g.payload.includes('LONG-LIVED') && JSON.parse(g.payload).token === 'ya29.short', 'google payload has access token only');
  ok(await rejects(C.mintGoogle(gdata, 'google-auth', async () => { throw new TypeError('cors'); })),
    'CORS/network failure delivers nothing');

  write('good.tsd', await C.deliver(req, signer, { name: 'oura', kind: 'file', exp: now + 600, payload: '{"session":"s3cret"}' }));
  write('wrapped.tsd', (await C.deliver(await r('wrapped'), signer, { name: 'oura', kind: 'file', exp: now + 600, payload: 'w' }))
    .replace(/(.{60})/g, '$1\n  '));
  write('expired.tsd', await C.deliver(await r('expired'), signer, { name: 'oura', kind: 'file', exp: now - 5, payload: 'x' }));
  write('over_ttl.tsd', await C.deliver(await r('over_ttl'), signer, { name: 'oura', kind: 'file', exp: now + 7200, payload: 'x' }));
  write('kind.tsd', await C.deliver(await r('kind'), signer, { name: 'oura', kind: 'google', exp: now + 600, payload: 'x' }));
  write('google.tsd', await C.deliver(await r('google'), signer, { name: 'google-agent', kind: 'google', exp: g.exp, payload: g.payload }));
  const tamper = (await C.deliver(await r('tamper'), signer, { name: 'oura', kind: 'file', exp: now + 600, payload: 'x' })).split('.');
  write('tampered.tsd', ['tsd1', enc({ ...dec(tamper[1]), exp: now + 900 }), ...tamper.slice(2)].join('.'));

  // An attacker who saw the link: ECDH to the public request key works, but they cannot sign as the page.
  const attacker = await C.openPageKey(new Uint8Array(32).fill(7), (await C.newPageKey(new Uint8Array(32).fill(7))).pageSeal);
  write('forged.tsd', await C.deliver(await r('forge'), attacker, { name: 'oura', kind: 'file', exp: now + 600, payload: 'ATTACKER' }));
  write('honest_after_forge.tsd', await C.deliver(await r('forge'), signer, { name: 'oura', kind: 'file', exp: now + 600, payload: 'honest' }));
}

(mode === 'setup' ? setup(...args) : deliverAll(...args)).catch((e) => { console.error(e); process.exit(1); });
