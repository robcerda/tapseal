# tapseal formats, v1

Normative. The reference implementations are `site/core.js` (page) and
`tapseal/core.py` (VM). A conforming implementation interoperates with both.

## Conventions

| Term | Meaning |
|---|---|
| `b64(x)` | base64url without padding (RFC 4648 §5). Decoders ignore whitespace, since chat apps wrap long strings |
| `json(o)` | UTF-8 JSON. Always authenticate the exact base64url text received, never a re-serialization |
| `HKDF(ikm, info, salt)` | HKDF-SHA-256, 32 byte output, empty salt unless given |
| `GCM(k, iv, pt, aad)` | AES-256-GCM, 12 byte random IV, 16 byte tag appended to the ciphertext |
| `SIG(key, msg)` | ECDSA P-256 with SHA-256, IEEE P1363 encoding (r ‖ s, exactly 64 bytes) |
| Public keys | P-256 uncompressed SEC1 points (65 bytes, leading `0x04`) |
| Names | `^[a-z0-9_-]{1,64}$`, matched against the whole string |
| Request ids | `^[A-Za-z0-9_-]{22}$` (16 random bytes) |
| Times | integer Unix seconds |
| `SKEW` | 120 seconds of tolerated clock difference |

## Keys

| Key | Lives | Purpose |
|---|---|---|
| Vault key `K`, 32 random bytes | Nowhere at rest. Wrapped per slot in `config.js` | Seals vault blobs and the page key |
| Slot secret | PRF output of an enrolled credential, or the paper key | Unwraps `K` |
| Page key, ECDSA P-256 | Private half sealed under `K` in `config.js`. Public half in `config.js` and pinned on the VM | Signs VM certificates and every delivery |
| VM identity, ECDSA P-256 | VM RAM only, regenerated after every reboot | Signs unlock requests |
| Request key, ECDH P-256 | VM RAM, one per request | Receives one delivery, then deleted |

The VM's disk holds sealed blobs and the pinned page public key. Neither can
sign or decrypt anything.

## Keyring (config.js)

```
window.TAPSEAL_CONFIG = {
  v: 1, rpId,
  salt: b64(32 random bytes),
  pageKey: b64(page public point),
  pageSeal: { iv, sealed },
  slots: [{ label, credId: b64, synced?: true, iv, wrapped }],
  paper: { iv, wrapped }
}
```

**Slot secret:** the WebAuthn PRF extension output `results.first`, requested
with `prf.eval = { first: salt }`. User verification is required.
- One salt serves every slot, because PRF output already differs per
  credential. `eval` is used rather than `evalByCredential` because some
  passkey providers implement only `eval`.
- A new salt is drawn at enrollment and at every rotation.

**Slot kinds:**
- By default, a slot must be a roaming hardware security key
  (`authenticatorAttachment` reported as `cross-platform`).
- A **synced passkey** (iCloud Keychain, 1Password, ...) is accepted only
  when the user explicitly chooses it, and is recorded with `synced: true`.
- Any one slot unwraps `K`, so a synced slot puts the whole vault behind that
  passkey account.

**Paper key:** 32 random bytes, shown as RFC 4648 base32 (52 characters) in
groups of 4.

**Wrapping:**
```
kek     = HKDF(secret, "tapseal-v1 keyring")
wrapped = GCM(kek, iv, K, aad = "tapseal-v1 keyring")
```

**Page key:**
```
sealed = GCM(HKDF(K, "tapseal-v1 page key"), iv, PKCS8(page private key), aad = "tapseal-v1 page key")
```

The page must refuse to run when `location.hostname != rpId`, and refuse to
enroll on a `*.github.io` host.

## Vault blob: `tsv1`

```
tsv1.<h>.<b64 iv>.<b64 ct>
h  = b64(json({ v: 1, name, kind: "file"|"google", created, ttl?, fmt? }))
ct = GCM(HKDF(K, "tapseal-v1 vault"), iv, secret, aad = "tsv1." + h)
```

**`file`:** `ttl` is the longest delivery lifetime allowed, 60 to 604800 seconds.

**`google`:**
- The secret is JSON `{client_id, client_secret?, refresh_token, scopes?, token_uri?}`.
- `fmt` is `google-auth` or `oauth2-go`.
- Deliveries are capped at 3600 seconds.

## VM certificate: `tsc1`

The page vouches for a VM identity key after the VM (re)starts.

```
tsc1.<h>.<b64 sig>
h   = b64(json({ v: 1, vmKey, pageKey, exp }))
sig = SIG(page key, "tsc1." + h)
```

**Lifetime:** at most 90 days.

**On first acceptance:** the VM pins `pageKey`.

**After that, the VM refuses a certificate unless all of these hold:**
1. `pageKey` equals the pinned key;
2. the signature verifies;
3. `vmKey` is its current identity.

## Unlock request: `tsr1`

```
tsr1.<h>.<b64 sig>
h   = b64(json({ v: 1, rid, name, epk: b64(request public point), exp }))
sig = SIG(VM identity, "tsr1." + h)
```

**On the VM:**
- The request's private key, `name` and `exp` are stored in RAM.
- That key is deleted once a delivery for `rid` decrypts, or at `exp`.
- `exp` is at most 900 seconds out.

## Unlock link

```
<page URL>#u=<tsv1 blob>&c=<tsc1 certificate>&r=<tsr1 request>
```

Everything rides in the fragment, which browsers do not send to the server.

**The page must refuse to proceed unless:**
1. `c` verifies under the configured `pageKey`, matches it, and has not expired;
2. `r` verifies under `c.vmKey`;
3. `now < r.exp <= now + 900 + SKEW`;
4. `r.name` equals the blob's claimed name before unlock, and its
   authenticated name after unseal.

## Delivery: `tsd1`

```
tsd1.<h>.<b64 epk>.<b64 iv>.<b64 ct>.<b64 sig>
h      = b64(json({ v: 1, rid, name, kind, exp }))
shared = ECDH(page ephemeral private, request public point)
k      = HKDF(shared, "tapseal-v1 delivery", salt = epk ‖ request public point)
ct     = GCM(k, iv, payload, aad = "tsd1." + h)
sig    = SIG(page key, "tsd1.<h>.<epk>.<iv>.<ct>")
```

**For `google`:** the payload is a freshly minted access token in the `fmt`
shape. The refresh token never leaves the page.

**The VM must:**
1. Verify `sig` under the pinned page key **before anything else**. An
   unsigned or forged delivery must not consume the request.
2. Find the request key for `rid`. Refuse if there is none, or it has expired.
3. Decrypt `ct`, then delete the request key regardless of what follows.
4. Refuse unless all of these hold:
   - `v == 1`;
   - `name` equals the request's name;
   - `kind` equals the stored blob's kind;
   - `now < exp <= now + cap + SKEW`, where `cap` is the blob's `ttl` for
     `file` and 3600 for `google`, never more than 7 days.
5. Write the payload to RAM at `<shm>/<name>` with mode 0600 and mtime = `exp`.

## Bundle: `tsb1`

```
tsb1.<b64 json([tsv1, ...])>
```

Unauthenticated as a whole; each blob authenticates itself. Used to move every
blob through a vault key rotation: open under the old `K`, re-seal under the
new one with the same header.

## Rotation

A new `K` and a new page key. Every slot is re-registered and the paper key is
new. Old slots, the old paper key, and every old `config.js` open only the old
`K`, which no current blob or page key uses.

The VM runs `import`, then `repin`, then `init --force`, and the user certifies
the new identity, which pins the new page key.

Old blobs in VM backups still open with the old `K`. If an old factor may be
compromised, re-issue the underlying secrets.

## Security properties

- **Disk, backups, chat history and agent logs, at any time, are not enough:**
  - they never open a blob or a past delivery;
  - they never yield a key that can sign requests or certificates;
  - they never yield a key that can forge deliveries.
- **Seeing a link is not enough to forge a delivery.** Deliveries carry the
  page key's signature.
- **Root on the live VM** can read live secrets, and use the identity while its
  certificate is valid. That is the accepted ceiling.
