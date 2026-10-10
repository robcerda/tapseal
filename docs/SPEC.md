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
  paper: { iv, wrapped },
  minCertIat?: time   // certificates issued before this are refused
}
```

**Slot secret:** the WebAuthn PRF extension output `results.first`, requested
with `prf.eval = { first: salt }`. User verification is required.
- One salt serves every slot, because PRF output already differs per
  credential. `eval` is used rather than `evalByCredential` because some
  passkey providers implement only `eval`.
- A new salt is drawn at enrollment and at every rotation.

**Slot kinds:**
- By default, a slot must be a hardware security key. At registration, the
  credential counts as synced, and is refused, if any of these hold:
  - the authenticator data flags have BE (backup eligible, bit 3) set;
  - `getTransports()` includes `hybrid` or `internal`;
  - `authenticatorAttachment` is not `cross-platform`;
  - any of this cannot be read.

  A phone passkey used over QR or Bluetooth reports `cross-platform`, which is
  why the attachment alone is not enough.
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
h   = b64(json({ v: 1, vmKey, pageKey, iat, exp }))
sig = SIG(page key, "tsc1." + h)
```

**Lifetime:** `exp - iat` at most 30 days (the page offers 1, 7 or 30, default 7).

**On first acceptance:** the VM pins `pageKey`.

**The VM refuses a certificate unless all of these hold:**
1. `pageKey` equals the pinned key, if one is pinned;
2. the signature verifies;
3. `vmKey` is its current identity;
4. it has not expired, and its lifetime is within 30 days.

**The page refuses a certificate** that is expired, over 30 days, or issued
before `config.minCertIat`. Committing a new `minCertIat` revokes every older
certificate without a rotation.

**The page cannot verify who sent a certify link.** The fingerprint it shows is
computed from the link. The page keeps a per device log of certificates it
issued, and on unlock says whether the presented certificate came from this
device.

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

Printed by `tapseal export` for the user to paste into a rotation.
Unauthenticated; each blob authenticates itself. Blobs that do not open under
the old `K` are skipped and listed by their claimed name.

## Rotation handoff: `tsk1`

```
tsk1.<h>.<b64 sig>
h   = b64(json({ v: 1, oldPageKey, newPageKey, iat, blobs: [tsv1, ...] }))
sig = SIG(old page key, "tsk1." + h)
```

`blobs` are the bundle's blobs re-sealed under the new `K`.

**The VM (`tapseal rotate`) refuses the handoff unless:**
1. a page key is pinned;
2. `oldPageKey` equals it;
3. the signature verifies under it.

**Then it:**
1. stores the blobs;
2. pins `newPageKey`;
3. drops the certificate;
4. creates a new identity.

There is no unauthenticated way to change the pin. Recovering a VM whose user
lost every factor means deleting its `TAPSEAL_HOME` by hand and starting over.

## Rotation

A new `K`, a new page key and a new salt.
- Every slot is re-registered, and the paper key is new.
- Old slots, the old paper key, and every old `config.js` open only the old
  `K`, which no current blob or page key uses.

The page emits a new `config.js` and a `tsk1` handoff. The VM runs
`tapseal rotate`, and the user certifies the new identity.

Old blobs in VM backups still open with the old `K`. If an old factor may be
compromised, re-issue the underlying secrets.

## VM housekeeping

`sweep` deletes only names tapseal creates:
- live secrets matching the name pattern;
- request files matching `<rid>.json`;
- its own temp files, `<name>.<8 hex>.tmp`, after 60 seconds;
- an expired certificate.

So a shared tmpfs directory is safe. `receive` checks that `TAPSEAL_SHM` is
tmpfs before it consumes anything.

## Security properties

- **Disk, backups, chat history and agent logs are not enough:**
  - they never open a blob or a past delivery;
  - they never yield a key that can sign requests or certificates;
  - they never yield a key that can forge deliveries;
  - this holds as long as they contain no image of the VM's memory.
- **A memory snapshot, hibernation image, or swapped page** taken while a
  request is open or a secret is live contains the request key, identity,
  certificate and live secrets. Treat those as live.
- **Seeing a link is not enough to forge a delivery.** Deliveries carry the
  page key's signature.
- **Root on the live VM** can read live secrets, and use the identity while its
  certificate is valid. That is the accepted ceiling.
- **Whoever controls the chat** between the user and the agent can act as the
  user toward the agent, and as the agent toward the user.
  - It cannot forge deliveries, handoffs or certificates.
  - It can ask the user to certify an identity it controls. Only the user's
    judgment stands in the way of that.
