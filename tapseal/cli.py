"""tapseal: VM side of hardware key gated secrets for agents on hosts you don't control.

  tapseal init [--force]       create the VM identity in RAM; print the certify link
  tapseal certify-link         print the certify link for the current identity
  tapseal certify [CERT]       accept the user's tsc1 certificate (stdin preferred)
  tapseal store [BLOB]         save a tsv1 vault blob (arg or stdin) under its name
  tapseal link NAME            issue a signed one time unlock request; print the URL
  tapseal receive [TSD]        open a tsd1 delivery (stdin preferred) into tmpfs
  tapseal status               identity, certificate, and live secrets
  tapseal lock [NAME]          delete live secret(s) now
  tapseal sweep [--loop N]     delete expired secrets, request keys, and certificate
  tapseal export               print all vault blobs as one tsb1 bundle
  tapseal import [BUNDLE]      store every blob in a tsb1 bundle
  tapseal repin                forget the pinned page key (after the user rotates their vault)

Env: TAPSEAL_HOME (default ~/.config/tapseal), TAPSEAL_URL (unlock page),
     TAPSEAL_SHM (default /dev/shm/tapseal; must be tmpfs).
"""
from __future__ import annotations

import argparse
import sys
import time

from . import __version__, core


def _stdin_or(val: str | None) -> str:
    return val if val else sys.stdin.read()


def fmt_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M %Z", time.localtime(ts))


def _print_certify() -> None:
    pub = core.identity_pub()
    print(core.certify_link())
    print(f"identity fingerprint: {core.fingerprint(core.b64d(pub))}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tapseal", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"tapseal {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init"); p.add_argument("--force", action="store_true")
    sub.add_parser("certify-link")
    p = sub.add_parser("certify"); p.add_argument("cert", nargs="?")
    p = sub.add_parser("store"); p.add_argument("blob", nargs="?")
    p = sub.add_parser("link"); p.add_argument("name"); p.add_argument("--ttl", type=int, default=core.REQUEST_TTL)
    p = sub.add_parser("receive"); p.add_argument("tsd", nargs="?")
    sub.add_parser("status")
    p = sub.add_parser("lock"); p.add_argument("name", nargs="?")
    p = sub.add_parser("sweep"); p.add_argument("--loop", type=int)
    sub.add_parser("export")
    p = sub.add_parser("import"); p.add_argument("bundle", nargs="?")
    sub.add_parser("repin")
    a = ap.parse_args(argv)

    try:
        if a.cmd == "init":
            core.init(a.force)
            _print_certify()
        elif a.cmd == "certify-link":
            _print_certify()
        elif a.cmd == "certify":
            page_key, exp, pinned = core.accept_cert(_stdin_or(a.cert))
            if pinned:
                print(f"pinned page key {core.fingerprint(core.b64d(page_key))}")
            print(f"identity certified until {fmt_time(exp)}")
        elif a.cmd == "store":
            name = core.store(_stdin_or(a.blob))
            print(f"stored {name} (header unverified here; only the user's keys can verify it)")
        elif a.cmd == "link":
            core.sweep()
            print(core.link(a.name, ttl=a.ttl))
        elif a.cmd == "receive":
            core.sweep()
            name, exp = core.receive(_stdin_or(a.tsd))
            print(f"{name} live until {fmt_time(exp)}")
        elif a.cmd == "status":
            core.sweep()
            s = core.status()
            print("identity: " + ("in RAM" if s["identity"] else "missing (run: tapseal init)"))
            print("certificate: " + (f"valid until {fmt_time(s['cert_exp'])}" if s["cert_exp"] else "none"))
            if s["page_key"]:
                print(f"page key: {core.fingerprint(core.b64d(s['page_key']))}")
            rows = core.live()
            names = {n for n, _ in rows}
            for name, exp in rows:
                print(f"live    {name:24} {int(exp - time.time()) // 60}m left")
            for name in core.stored():
                if name not in names:
                    print(f"locked  {name}")
        elif a.cmd == "lock":
            for n in core.lock(a.name):
                print(f"locked {n}")
        elif a.cmd == "sweep":
            while True:
                for n in core.sweep():
                    print(f"{time.strftime('%H:%M:%S')} expired {n}", file=sys.stderr)
                if not a.loop:
                    break
                time.sleep(a.loop)
        elif a.cmd == "export":
            print(core.export_bundle())
        elif a.cmd == "import":
            names = core.import_bundle(_stdin_or(a.bundle))
            print("stored " + (", ".join(names) or "nothing"))
        elif a.cmd == "repin":
            core.repin()
            print("page key and certificate forgotten; the next certificate pins a new page key")
    except core.TapsealError as e:
        print(f"tapseal: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
