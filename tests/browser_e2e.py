"""Full page flow in Chromium with a virtual PRF authenticator:
selftest -> enroll -> seal -> store -> link -> unlock -> deliver -> receive,
plus forward secrecy, request pinning, and paper-key recovery at #recover.
Fails on any console error or CSP violation.

Run: python3 tests/browser_e2e.py   (needs `playwright`; set PW_CHANNEL=chrome to use installed Chrome)
"""
import functools
import http.server
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
PORT = 8765
tmp = Path(tempfile.mkdtemp())
env = {**os.environ, "TAPSEAL_HOME": str(tmp / "home"), "TAPSEAL_SHM": str(tmp / "shm"),
       "TAPSEAL_URL": f"http://localhost:{PORT}/", "PYTHONPATH": str(ROOT)}
VM = [sys.executable, "-m", "tapseal"]


def vm(*args, check=True):
    return subprocess.run(VM + list(args), env=env, capture_output=True, text=True, check=check)


vm_key = vm("init").stdout.strip()

class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


handler = functools.partial(Quiet, directory=str(SITE))
srv = http.server.ThreadingHTTPServer(("localhost", PORT), handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()

config = {"js": "window.TAPSEAL_CONFIG = null;"}
problems = []
n = 0


def ok(cond, msg):
    global n
    if not cond:
        print("FAIL", msg, problems)
        sys.exit(1)
    n += 1
    print(f"b{n} {msg}: OK")


with sync_playwright() as p:
    b = p.chromium.launch(channel=os.environ.get("PW_CHANNEL") or None)
    page = b.new_page()
    page.on("console", lambda m: m.type == "error" and problems.append(m.text))
    page.on("pageerror", lambda e: problems.append(str(e)))
    page.route("**/config.js", lambda r: r.fulfill(status=200, content_type="text/javascript", body=config["js"]))
    page.add_init_script("document.addEventListener('securitypolicyviolation', e => console.error('CSP ' + e.violatedDirective))")

    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "ctap2Version": "ctap2_1", "transport": "usb",
        "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True,
        "hasPrf": True, "automaticPresenceSimulation": True}})

    def goto(frag):
        page.goto(f"http://localhost:{PORT}/" + frag)
        page.wait_for_selector("h1")

    def deliver_from(link, ttl="300"):
        page.goto(link)
        page.wait_for_selector("text=Unlock request")
        page.click("text=Unlock with security key")
        page.wait_for_selector("text=Verified: oura", timeout=15000)
        page.select_option("select", ttl)
        page.click("text=Deliver to VM")
        page.wait_for_selector("text=Paste this into chat")
        return page.input_value("textarea")

    goto("#selftest")
    page.click("text=Run self-test")
    page.wait_for_selector("text=PASS: this phone and key can run tapseal.", timeout=15000)
    ok(True, "PRF self-test passes")

    goto("#enroll")
    page.click("text=Start")
    page.fill("input[placeholder^='e.g. yk-nfc']", "yk-nfc")
    page.click("text=Register key")
    page.wait_for_selector("text=Registered yk-nfc.", timeout=15000)
    ok(True, "key registered with two PRF touches")
    page.fill("input[placeholder='from: tapseal init']", vm_key)
    page.click("text=Generate config.js")
    page.wait_for_selector(".paper")
    paper = page.inner_text(".paper").strip()
    ok("Confirm you wrote down the paper key." in page.inner_text(".status"), "config withheld until paper key confirmed")
    page.check(".warn input[type=checkbox]")
    page.click("text=Generate config.js")
    page.wait_for_selector("text=Warning: only one key enrolled.")
    config["js"] = page.input_value("textarea")
    ok('"vmKey"' in config["js"] and '"wrapped"' in config["js"] and "localhost" in config["js"], "config.js generated")

    goto("")
    ok("yk-nfc" in page.inner_text("main"), "home shows enrolled key")

    goto("#seal")
    page.fill("input[placeholder='e.g. oura']", "oura")
    page.fill("textarea", '{"session":"s3cret"}')
    page.click("text=Seal with security key")
    page.wait_for_selector("text=Vault blob for oura", timeout=15000)
    blob = page.input_value("section:has-text('Vault blob') textarea")
    ok(blob.startswith("tsv1.") and page.input_value("textarea >> nth=0") == "", "sealed; plaintext field cleared")
    vm("store", blob)

    link = vm("link", "oura").stdout.strip()
    tsd = deliver_from(link)
    r = vm("receive", tsd, check=False)
    ok(r.returncode == 0 and (tmp / "shm" / "oura").read_text() == '{"session":"s3cret"}', "phone delivery opens on VM")
    ok(page.locator("text=Deliver to VM").count() == 0, "deliver button gone after one use")
    r = vm("receive", tsd, check=False)
    ok(r.returncode != 0 and "no open request" in r.stderr, "same delivery cannot be opened twice (request key consumed)")

    goto("#u=" + link.split("#u=")[1].split("&r=")[0])
    ok(page.locator("text=no unlock request").count() == 1, "link without a signed request is refused before unlock")

    oenv = {**env, "TAPSEAL_HOME": tempfile.mkdtemp()}
    subprocess.run(VM + ["init"], env=oenv, capture_output=True, check=True)
    subprocess.run(VM + ["store", blob], env=oenv, capture_output=True, check=True)
    imposter = subprocess.run(VM + ["link", "oura"], env=oenv, capture_output=True, text=True, check=True).stdout.strip()
    page.goto(imposter)
    page.wait_for_selector("text=not issued by your VM")
    ok(page.locator("text=Unlock with security key").count() == 0, "request signed by another VM is refused")

    goto("#u=" + link.split("#u=")[1])
    ok(page.locator("text=Paper").count() == 0 and page.locator("input").count() == 0, "unlock page never offers paper-key entry")

    goto("#recover")
    page.fill("input.mono", paper)
    page.click("text=Unlock with paper key")
    page.wait_for_selector("text=Paper key accepted", timeout=15000)
    ok(page.locator("text=Register key").count() == 1, "paper key recovery at #recover opens key management")

    goto("#enroll")
    ok(page.locator("text=Unlock the existing keyring").count() == 1, "enroll on existing keyring requires unlock first")

    b.close()

srv.shutdown()
problems = [x for x in problems if "Failed to load resource" not in x]
ok(not problems, "no console errors or CSP violations")
