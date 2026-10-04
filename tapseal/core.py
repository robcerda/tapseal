"""tapseal VM side. Never holds a vault key, and keeps nothing on disk that can sign or decrypt.

On disk (TAPSEAL_HOME): sealed vault blobs, and the pinned public page key.
In RAM (TAPSEAL_SHM, must be tmpfs):
  identity.pem   VM identity signing key, regenerated after every reboot
  identity.cert  the user's certificate for it, made with one tap on the unlock page
  .requests/     one time ECDH keys, deleted on receipt or after 15 minutes
  <name>         live secrets, deleted at expiry

Formats are specified in docs/SPEC.md.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NAME_RE = re.compile(r"[a-z0-9_-]{1,64}")
RID_RE = re.compile(r"[A-Za-z0-9_-]{22}")
MAX_LIFETIME = 7 * 86400
GOOGLE_MAX = 3600
REQUEST_TTL = 900
SKEW = 120
TMP_GRACE = 60
RAM_FS = {"tmpfs", "ramfs"}


class TapsealError(Exception):
    pass


@dataclass(frozen=True)
class Paths:
    home: Path
    shm: Path

    @property
    def vault(self) -> Path:
        return self.home / "vault"

    @property
    def page_pub(self) -> Path:
        return self.home / "page.pub"

    @property
    def identity(self) -> Path:
        return self.shm / "identity.pem"

    @property
    def cert(self) -> Path:
        return self.shm / "identity.cert"

    @property
    def requests(self) -> Path:
        return self.shm / ".requests"


def paths() -> Paths:
    return Paths(
        home=Path(os.environ.get("TAPSEAL_HOME", "~/.config/tapseal")).expanduser(),
        shm=Path(os.environ.get("TAPSEAL_SHM", "/dev/shm/tapseal")),
    )


def valid_name(name: object) -> bool:
    return isinstance(name, str) and NAME_RE.fullmatch(name) is not None


# ---------- encoding helpers ----------

def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        raise TapsealError("malformed base64") from None


def json_part(s: str) -> dict:
    try:
        v = json.loads(b64d(s))
    except (ValueError, TapsealError):
        raise TapsealError("unreadable header") from None
    if not isinstance(v, dict):
        raise TapsealError("unreadable header")
    return v


def clean(text: str) -> str:
    """Chat apps wrap long strings; whitespace is never meaningful."""
    return re.sub(r"\s+", "", text)


def split(text: str, prefix: str, n: int) -> list[str]:
    p = clean(text).split(".")
    if len(p) != n or p[0] != prefix:
        raise TapsealError(f"not a {prefix} string")
    return p


def private_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = os.lstat(p)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise TapsealError(f"{p} is not a real directory; refusing")
    if st.st_uid != os.getuid():
        raise TapsealError(f"{p} is owned by another user; refusing")
    os.chmod(p, 0o700)


def write_private(path: Path, data: bytes, mtime: int | None = None) -> None:
    tmp = path.with_name(f"{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    if mtime is not None:
        os.utime(tmp, (time.time(), mtime))
    os.replace(tmp, path)


def fs_type(p: Path) -> str | None:
    """Filesystem type of p from /proc/mounts (Linux), or None if unknown."""
    try:
        mounts = Path("/proc/mounts").read_text().splitlines()
    except OSError:
        return None
    target = str(p.resolve())
    best, kind = "", None
    for line in mounts:
        f = line.split()
        if len(f) < 3:
            continue
        mnt = f[1].replace("\\040", " ")
        if (target == mnt or target.startswith(mnt.rstrip("/") + "/")) and len(mnt) > len(best):
            best, kind = mnt, f[2]
    return kind


def ram_dir() -> Path:
    """The RAM directory, created and checked. Keys must never land on disk."""
    P = paths()
    private_dir(P.shm)
    if os.environ.get("TAPSEAL_ALLOW_DISK") != "1":
        kind = fs_type(P.shm)
        if kind not in RAM_FS:
            raise TapsealError(f"{P.shm} is on {kind or 'an unknown filesystem'}, not tmpfs. Keys would reach disk. "
                               "Point TAPSEAL_SHM at tmpfs (TAPSEAL_ALLOW_DISK=1 overrides, for tests only).")
    return P.shm


def raw_point(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def load_point(b64: str) -> ec.EllipticCurvePublicKey:
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b64d(b64))
    except (ValueError, TapsealError):
        raise TapsealError("bad P-256 public key") from None


def fingerprint(raw: bytes) -> str:
    return b64e(hashlib.sha256(raw).digest()[:9])


def sign(priv: ec.EllipticCurvePrivateKey, msg: bytes) -> bytes:
    """ECDSA P-256 / SHA-256 in IEEE P1363 form (r || s), which WebCrypto verifies."""
    r, s = decode_dss_signature(priv.sign(msg, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify(pub: ec.EllipticCurvePublicKey, sig_b64: str, msg: bytes) -> bool:
    sig = b64d(sig_b64)
    if len(sig) != 64:
        return False
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        pub.verify(der, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ---------- identity (in RAM) and its certificate ----------

def init(force: bool = False) -> str:
    """Create the VM identity in RAM. After a reboot it is gone and init runs again."""
    P = paths()
    ram_dir()
    if P.identity.exists() and not force:
        raise TapsealError("identity already exists in RAM; pass --force to replace it (needs a new certificate)")
    priv = ec.generate_private_key(ec.SECP256R1())
    write_private(P.identity, priv.private_bytes(serialization.Encoding.PEM,
                                                 serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()))
    P.cert.unlink(missing_ok=True)
    return identity_pub()


def load_identity() -> ec.EllipticCurvePrivateKey:
    P = paths()
    if not P.identity.exists():
        raise TapsealError("no identity in RAM (first run, or the host rebooted). Run: tapseal init, "
                           "then send the user the certify link")
    return serialization.load_pem_private_key(P.identity.read_bytes(), password=None)


def identity_pub() -> str:
    return b64e(raw_point(load_identity().public_key()))


def certify_link(url: str | None = None) -> str:
    return f"{page_url(url)}#certify={identity_pub()}"


def page_url(url: str | None = None) -> str:
    url = url or os.environ.get("TAPSEAL_URL")
    if not url:
        raise TapsealError("set TAPSEAL_URL to the unlock page, e.g. https://unlock.example.com/")
    return url.rstrip("/") + "/"


def pinned_page_key() -> str | None:
    P = paths()
    return P.page_pub.read_text().strip() if P.page_pub.exists() else None


def accept_cert(text: str) -> tuple[str, int, bool]:
    """Store the user's certificate for the current identity. Pins the page key on first use."""
    p = split(text, "tsc1", 3)
    h = json_part(p[1])
    vm_key, page_key, exp = h.get("vmKey"), h.get("pageKey"), h.get("exp")
    if h.get("v") != 1 or not isinstance(vm_key, str) or not isinstance(page_key, str) or not isinstance(exp, int):
        raise TapsealError("malformed certificate")
    if vm_key != identity_pub():
        raise TapsealError("certificate is for a different identity (was init run again?). Send a new certify link.")
    pinned = pinned_page_key()
    if pinned and page_key != pinned:
        raise TapsealError("certificate was signed by a page key that is not the pinned one. "
                           "If the user rotated their vault, run: tapseal repin")
    if not verify(load_point(page_key), p[2], f"tsc1.{p[1]}".encode()):
        raise TapsealError("certificate signature is invalid")
    if exp <= int(time.time()):
        raise TapsealError("certificate already expired")
    P = paths()
    newly_pinned = False
    if not pinned:
        private_dir(P.home)
        write_private(P.page_pub, page_key.encode())
        newly_pinned = True
    write_private(P.cert, clean(text).encode())
    return page_key, exp, newly_pinned


def current_cert() -> str:
    P = paths()
    if not P.cert.exists():
        raise TapsealError("identity is not certified. Send the user the link from: tapseal certify-link")
    cert = P.cert.read_text().strip()
    if json_part(cert.split(".")[1]).get("exp", 0) <= time.time():
        raise TapsealError("certificate expired. Send the user the link from: tapseal certify-link")
    return cert


def repin() -> None:
    paths().page_pub.unlink(missing_ok=True)
    paths().cert.unlink(missing_ok=True)


# ---------- vault blobs (stored, never opened here) ----------

def store(text: str) -> str:
    blob = clean(text)
    p = split(blob, "tsv1", 4)
    name = json_part(p[1]).get("name", "")
    if not valid_name(name):
        raise TapsealError("bad name in blob")
    P = paths()
    private_dir(P.vault)
    write_private(P.vault / f"{name}.tsv", blob.encode())
    return name


def stored() -> list[str]:
    P = paths()
    if not P.vault.exists():
        return []
    return sorted(p.stem for p in P.vault.glob("*.tsv"))


def stored_header(name: str) -> dict:
    P = paths()
    path = P.vault / f"{name}.tsv"
    if not path.exists():
        raise TapsealError(f"no vault blob for {name}; ask the user to seal it and send the tsv1 string")
    return json_part(path.read_text().split(".")[1])


def export_bundle() -> str:
    P = paths()
    blobs = [(P.vault / f"{n}.tsv").read_text().strip() for n in stored()]
    return "tsb1." + b64e(json.dumps(blobs).encode())


def import_bundle(text: str) -> list[str]:
    p = split(text, "tsb1", 2)
    try:
        blobs = json.loads(b64d(p[1]))
    except ValueError:
        raise TapsealError("malformed bundle") from None
    if not isinstance(blobs, list) or not all(isinstance(b, str) for b in blobs):
        raise TapsealError("malformed bundle")
    return [store(b) for b in blobs]


# ---------- unlock requests ----------

def make_request(name: str, ttl: int = REQUEST_TTL) -> str:
    """Mint a one time ECDH key in RAM and return the signed tsr1 request for it."""
    if not valid_name(name):
        raise TapsealError("bad name")
    if not 60 <= ttl <= REQUEST_TTL:
        raise TapsealError(f"request ttl must be 60..{REQUEST_TTL} seconds")
    identity = load_identity()
    P = paths()
    ram_dir()
    private_dir(P.requests)
    eph = ec.generate_private_key(ec.SECP256R1())
    rid = b64e(secrets.token_bytes(16))
    exp = int(time.time()) + ttl
    record = {
        "name": name,
        "exp": exp,
        "key": eph.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption()).decode(),
    }
    write_private(P.requests / f"{rid}.json", json.dumps(record).encode(), mtime=exp)
    h = b64e(json.dumps({"v": 1, "rid": rid, "name": name, "epk": b64e(raw_point(eph.public_key())),
                         "exp": exp}, separators=(",", ":")).encode())
    return f"tsr1.{h}.{b64e(sign(identity, f'tsr1.{h}'.encode()))}"


def link(name: str, url: str | None = None, ttl: int = REQUEST_TTL) -> str:
    P = paths()
    if not valid_name(name):
        raise TapsealError("bad name")
    stored_header(name)
    cert = current_cert()
    base = page_url(url)
    req = make_request(name, ttl)
    return f"{base}#u={(P.vault / f'{name}.tsv').read_text().strip()}&c={cert}&r={req}"


# ---------- deliveries ----------

def receive(text: str) -> tuple[str, int]:
    p = split(text, "tsd1", 6)
    h = p[1]
    page_key = pinned_page_key()
    if not page_key:
        raise TapsealError("no page key pinned yet; the user must certify this VM first")
    if not verify(load_point(page_key), p[5], ".".join(p[:5]).encode()):
        raise TapsealError("delivery is not signed by the user's page key. Refusing it, "
                           "and treat whoever supplied it as hostile.")

    rid = json_part(h).get("rid", "")
    if not isinstance(rid, str) or not RID_RE.fullmatch(rid):
        raise TapsealError("bad request id in delivery")
    P = paths()
    req_path = P.requests / f"{rid}.json"
    try:
        req = json.loads(req_path.read_text())
    except FileNotFoundError:
        raise TapsealError("no open request for this delivery: already received, expired, "
                           "or made for another VM. Send a new link.") from None
    now = int(time.time())
    if req["exp"] <= now:
        req_path.unlink(missing_ok=True)
        raise TapsealError("the unlock request expired before delivery. Send a new link.")

    priv = serialization.load_pem_private_key(req["key"].encode(), password=None)
    mine = raw_point(priv.public_key())
    epk_raw, iv, ct = b64d(p[2]), b64d(p[3]), b64d(p[4])
    try:
        epk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), epk_raw)
        shared = priv.exchange(ec.ECDH(), epk)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=epk_raw + mine,
                   info=b"tapseal-v1 delivery").derive(shared)
        payload = AESGCM(key).decrypt(iv, ct, f"tsd1.{h}".encode())
    except Exception:
        raise TapsealError("delivery did not open: corrupted or altered") from None
    req_path.unlink(missing_ok=True)  # one time, whatever happens next: forward secrecy and no replay

    header = json_part(h)  # authenticated via AAD and the page signature from here on
    name, kind, exp = header.get("name"), header.get("kind"), header.get("exp")
    if header.get("v") != 1 or name != req["name"] or not isinstance(exp, int):
        raise TapsealError("delivery header does not match its request")
    blob = stored_header(name)
    if kind != blob.get("kind"):
        raise TapsealError(f"{name}: delivery kind does not match the stored secret")
    cap = GOOGLE_MAX if kind == "google" else min(int(blob.get("ttl", MAX_LIFETIME)), MAX_LIFETIME)
    if exp <= now:
        raise TapsealError(f"{name}: delivery already expired")
    if exp > now + cap + SKEW:
        raise TapsealError(f"{name}: expiry exceeds the secret's allowed lifetime")

    ram_dir()
    write_private(P.shm / name, payload, mtime=exp)  # mtime = expiry; sweep relies on it
    return name, exp


# ---------- live secrets ----------

RESERVED = {"identity.pem", "identity.cert"}


def live() -> list[tuple[str, float]]:
    P = paths()
    if not P.shm.exists():
        return []
    return sorted((p.name, p.stat().st_mtime) for p in P.shm.iterdir()
                  if p.is_file() and not p.name.endswith(".tmp") and p.name not in RESERVED)


def lock(name: str | None = None) -> list[str]:
    P = paths()
    if name is not None and not valid_name(name):
        raise TapsealError("bad name")
    targets = [name] if name else [n for n, _ in live()]
    gone = []
    for n in targets:
        try:
            (P.shm / n).unlink()
            gone.append(n)
        except FileNotFoundError:
            pass
    return gone


def sweep() -> list[str]:
    """Delete expired secrets, expired request keys, an expired certificate, and stale temp files."""
    P = paths()
    now = time.time()
    gone = []
    for d in (P.shm, P.requests):
        if not d.exists():
            continue
        for p in d.iterdir():
            try:
                if not p.is_file() or p.name == "identity.pem":
                    continue
                if p.name == "identity.cert":
                    if json_part(p.read_text().split(".")[1]).get("exp", 0) <= now:
                        p.unlink()
                        gone.append("certificate")
                    continue
                m = p.stat().st_mtime
                if (p.name.endswith(".tmp") and m <= now - TMP_GRACE) or (not p.name.endswith(".tmp") and m <= now):
                    p.unlink()
                    gone.append(p.name if d == P.shm else f"request {p.stem}")
            except (FileNotFoundError, TapsealError, IndexError):
                pass
    return gone


def status() -> dict:
    P = paths()
    info = {"identity": P.identity.exists(), "cert_exp": None, "page_key": pinned_page_key()}
    if P.cert.exists():
        try:
            info["cert_exp"] = json_part(P.cert.read_text().split(".")[1]).get("exp")
        except (TapsealError, IndexError):
            pass
    return info

