"""Page crypto (Node WebCrypto, site/core.js) <-> VM side (Python, tapseal.core).

Run: python3 -m unittest tests/test_interop.py   (needs node and `cryptography`)
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tapseal import core  # noqa: E402


def node(*args):
    r = subprocess.run(["node", str(ROOT / "tests/core.test.js"), *args], capture_output=True, text=True)
    print(r.stdout, end="")
    if r.returncode:
        raise AssertionError("node side failed:\n" + r.stdout + r.stderr)
    return r.stdout


class Interop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = cls.dir = Path(cls.tmp.name)
        os.environ.update(TAPSEAL_HOME=str(t / "home"), TAPSEAL_SHM=str(t / "shm"),
                          TAPSEAL_URL="https://unlock.example.com/", TAPSEAL_ALLOW_DISK="1")
        os.environ["TAPSEAL_SHM"] = str(t / "other-shm")
        cls.other = core.init()
        os.environ["TAPSEAL_SHM"] = str(t / "shm")
        cls.pub = core.init()

        out = node("setup", cls.pub, cls.other, str(t))
        cls.node_fp = out.strip().splitlines()[-1].split()[-1]
        core.accept_cert(cls.read("cert.tsc"))
        core.store(cls.read("vault.tsv"))
        core.store(cls.read("google.tsv"))

        reqs = {k: core.make_request(n) for k, n in [
            ("good", "oura"), ("wrapped", "oura"), ("expired", "oura"), ("over_ttl", "oura"), ("kind", "oura"),
            ("google", "google-agent"), ("tamper", "oura"), ("forge", "oura")]}
        # A request with a 10 year lifetime, signed by the real identity: the page must refuse it.
        h = core.b64e(json.dumps({"v": 1, "rid": "A" * 22, "name": "oura", "epk": cls.pub,
                                  "exp": int(time.time()) + 10 * 365 * 86400}).encode())
        reqs["longlived"] = f"tsr1.{h}.{core.b64e(core.sign(core.load_identity(), f'tsr1.{h}'.encode()))}"
        reqs["otherVmKey"] = cls.other
        (t / "requests.json").write_text(json.dumps(reqs))
        node("deliver", str(t))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def read(cls, f):
        return (cls.dir / f).read_text()

    def shm(self, name=""):
        return Path(os.environ["TAPSEAL_SHM"]) / name

    def test_fingerprint_matches_page(self):
        self.assertEqual(core.fingerprint(core.b64d(self.pub)), self.node_fp)

    def test_receive_good_then_replay_refused(self):
        name, exp = core.receive(self.read("good.tsd"))
        self.assertEqual(name, "oura")
        self.assertEqual(self.shm("oura").read_text(), '{"session":"s3cret"}')
        self.assertEqual(stat.S_IMODE(self.shm("oura").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.shm().stat().st_mode), 0o700)
        self.assertAlmostEqual(self.shm("oura").stat().st_mtime, exp, delta=1)
        with self.assertRaisesRegex(core.TapsealError, "no open request"):
            core.receive(self.read("good.tsd"))
        core.lock("oura")
        self.assertFalse(self.shm("oura").exists())

    def test_forged_delivery_refused_and_honest_one_still_works(self):
        with self.assertRaisesRegex(core.TapsealError, "not signed by the user's page key"):
            core.receive(self.read("forged.tsd"))
        self.assertEqual(core.receive(self.read("honest_after_forge.tsd"))[0], "oura")
        self.assertEqual(self.shm("oura").read_text(), "honest")

    def test_google_token_only(self):
        core.receive(self.read("google.tsd"))
        self.assertNotIn("LONG-LIVED", self.shm("google-agent").read_text())

    def test_whitespace_wrapped_paste(self):
        core.receive(self.read("wrapped.tsd"))

    def test_lifetime_and_kind_enforced(self):
        with self.assertRaisesRegex(core.TapsealError, "already expired"):
            core.receive(self.read("expired.tsd"))
        with self.assertRaisesRegex(core.TapsealError, "allowed lifetime"):
            core.receive(self.read("over_ttl.tsd"))
        with self.assertRaisesRegex(core.TapsealError, "kind"):
            core.receive(self.read("kind.tsd"))

    def test_tampered_delivery_refused(self):
        with self.assertRaisesRegex(core.TapsealError, "not signed"):
            core.receive(self.read("tampered.tsd"))

    def test_garbage_is_a_clean_error(self):
        for junk in ["", "tsd1.!!!.a.b.c.d", "tsd1.e30.a.b.c.d", "hello", "tsc1.e30.x", "tsb1.!!"]:
            with self.assertRaises(core.TapsealError):
                core.receive(junk)

    def test_certificates(self):
        with self.assertRaisesRegex(core.TapsealError, "different identity"):
            core.accept_cert(self.read("cert_wrong_identity.tsc"))
        with self.assertRaisesRegex(core.TapsealError, "not the pinned one"):
            core.accept_cert(self.read("cert_foreign_page.tsc"))
        page_key, exp, pinned = core.accept_cert(self.read("cert.tsc"))
        self.assertFalse(pinned)

    def test_link_carries_cert_and_request(self):
        url = core.link("oura")
        self.assertTrue(url.startswith("https://unlock.example.com/#u=tsv1."))
        self.assertIn("&c=tsc1.", url)
        self.assertIn("&r=tsr1.", url)

    def test_names_must_match_exactly(self):
        for bad in ["oura\n", "../oura", "identity.pem", "OURA"]:
            with self.assertRaises(core.TapsealError):
                core.make_request(bad)

    def test_export_lists_every_blob(self):
        blobs = json.loads(core.b64d(core.export_bundle().split(".")[1]))
        self.assertEqual(len(blobs), 2)

    def isolated(self):
        """Copy the VM state so a test can change pins without affecting the others."""
        t = Path(tempfile.mkdtemp(dir=self.dir))
        shutil.copytree(os.environ["TAPSEAL_HOME"], t / "home")
        shutil.copytree(os.environ["TAPSEAL_SHM"], t / "shm")
        saved = os.environ["TAPSEAL_HOME"], os.environ["TAPSEAL_SHM"]
        os.environ.update(TAPSEAL_HOME=str(t / "home"), TAPSEAL_SHM=str(t / "shm"))
        self.addCleanup(lambda: os.environ.update(TAPSEAL_HOME=saved[0], TAPSEAL_SHM=saved[1]))

    def test_rotation_needs_a_handoff_signed_by_the_old_page_key(self):
        self.isolated()
        old_identity = core.identity_pub()
        with self.assertRaisesRegex(core.TapsealError, "hostile"):
            core.rotate(self.read("handoff_forged.tsk"))
        self.assertNotEqual(core.pinned_page_key(), json.loads(self.read("state2.json"))["page"]["pageKey"])
        names, link = core.rotate(self.read("handoff.tsk"))
        self.assertEqual(sorted(names), ["google-agent", "oura"])
        self.assertEqual(core.pinned_page_key(), json.loads(self.read("state2.json"))["page"]["pageKey"])
        self.assertNotEqual(core.identity_pub(), old_identity)
        self.assertIn("#certify=", link)
        self.assertFalse(core.paths().cert.exists())
        with self.assertRaisesRegex(core.TapsealError, "not from the pinned page key"):
            core.rotate(self.read("handoff.tsk"))  # replaying it after the repin fails

    def test_certificate_lifetime_capped_on_vm(self):
        with self.assertRaisesRegex(core.TapsealError, "30 days"):
            core.accept_cert(self.read("cert_long.tsc"))

    def test_sweep_touches_only_tapseal_files(self):
        self.shm().mkdir(exist_ok=True)
        foreign = [self.shm("other-app.lock"), self.shm("page.pub"), self.shm("Mixed.Case")]
        for f in foreign:
            f.write_text("x")
            os.utime(f, (1, 1))
        core.sweep()
        self.assertTrue(all(f.exists() for f in foreign))
        for f in foreign:
            f.unlink()

    def test_receive_checks_tmpfs_before_consuming(self):
        req_dir = self.shm(".requests")
        before = len(list(req_dir.glob("*.json")))
        os.environ.pop("TAPSEAL_ALLOW_DISK")
        try:
            if core.fs_type(self.shm()) not in core.RAM_FS:
                with self.assertRaisesRegex(core.TapsealError, "not tmpfs"):
                    core.receive(self.read("wrapped.tsd"))
                self.assertEqual(len(list(req_dir.glob("*.json"))), before)
        finally:
            os.environ["TAPSEAL_ALLOW_DISK"] = "1"

    def test_fs_type_uses_last_stacked_mount(self):
        from unittest import mock
        table = "tmpfs /x\\040y tmpfs rw 0 0\next4 /x\\040y ext4 rw 0 0\n"
        real_read = Path.read_text
        with mock.patch.object(Path, "read_text", lambda self_, *a, **k: table if str(self_) == "/proc/mounts"
                               else real_read(self_, *a, **k)), \
             mock.patch.object(Path, "resolve", lambda self_, *a, **k: self_):
            self.assertEqual(core.fs_type(Path("/x y")), "ext4")


    def test_refuses_disk_without_override(self):
        os.environ.pop("TAPSEAL_ALLOW_DISK")
        try:
            if core.fs_type(self.shm()) not in core.RAM_FS:
                with self.assertRaisesRegex(core.TapsealError, "not tmpfs"):
                    core.make_request("oura")
        finally:
            os.environ["TAPSEAL_ALLOW_DISK"] = "1"

    def test_sweep_removes_expired_secret_and_request(self):
        core.make_request("oura", ttl=60)
        f = self.shm("stale")
        f.write_text("x")
        os.utime(f, (1, 1))
        for p in self.shm(".requests").glob("*.json"):
            if json.loads(p.read_text())["exp"] <= time.time() + 61:
                os.utime(p, (1, 1))
        gone = core.sweep()
        self.assertIn("stale", gone)
        self.assertTrue(any(g.startswith("request ") for g in gone))
        self.assertTrue(core.paths().identity.exists() and core.paths().cert.exists())

    def test_cli_status(self):
        r = subprocess.run([sys.executable, "-m", "tapseal", "status"], capture_output=True, text=True,
                           cwd=ROOT, env=os.environ)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("certificate: valid until", r.stdout)


if __name__ == "__main__":
    unittest.main()
