#!/usr/bin/env python3
"""End-to-end test of the shim with the REAL nak binary and real public relays.

Usage: NAK_BIN=/path/to/nak PKG=/path/with/node_modules python3 -I tests/e2e_local.py
Uses a throwaway key in a temp HOME. Signs nothing that gets published.
"""
import json, os, re, shutil, signal, subprocess, sys, tempfile, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SHIM = os.path.join(HERE, "..", "shim", "nakbunker.py")
NAK = os.environ["NAK_BIN"]
PORT = int(os.environ.get("TEST_PORT", "18951"))
RELAYS = os.environ.get("TEST_RELAYS", "wss://nostr.oxtr.dev\nwss://offchain.pub\nwss://relay.snort.social")
PW = "correct horse battery"
FAILS = 0


def check(label, cond, extra=""):
    global FAILS
    print(("PASS" if cond else "FAIL") + ": " + label + (f"  [{extra}]" if extra and not cond else ""), flush=True)
    FAILS += 0 if cond else 1


def get(path):
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=10) as r:
        return r.read().decode()


def status():
    return json.loads(get("/api/status"))


def post(path, data, token):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", method="POST",
                                 data=urllib.parse.urlencode(data).encode(),
                                 headers={"X-CSRF": token} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def wait(pred, secs=60):
    end = time.time() + secs
    while time.time() < end:
        s = status()
        if pred(s):
            return s
        time.sleep(1)
    return status()


def start_shim(home):
    env = dict(os.environ, NAK_BIN=NAK, NAK_HOME=home, PORT=str(PORT))
    p = subprocess.Popen([sys.executable, "-I", SHIM], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    for _ in range(50):
        try:
            get("/api/status")
            break
        except Exception:
            time.sleep(0.2)
    page = get("/")
    token = re.search(r'const T="([^"]+)"', page).group(1)
    return p, token


CLIENT_HEX = os.urandom(32).hex()


def client(uri, mode=""):
    out = subprocess.run(["node", os.path.join(HERE, "nip46_client.mjs"), uri, mode, CLIENT_HEX], capture_output=True, text=True, timeout=90)
    try:
        return json.loads(out.stdout.strip().splitlines()[-1])
    except Exception:
        return {"error": out.stderr[-300:]}


import urllib.parse  # noqa: E402

home = tempfile.mkdtemp(prefix="nakbunker-e2e-")
p, tok = start_shim(home)
try:
    s = status()
    check("fresh install shows setup, nak not started", s["state"] == "setup")
    check("POST without CSRF token refused", post("/api/setup", {"mode": "generate"}, None)[0] == 403)
    check("short password refused", post("/api/setup", {"mode": "generate", "password": "short", "relays": RELAYS}, tok)[0] == 400)
    check("bad ncryptsec password refused before saving",
          post("/api/setup", {"mode": "import-ncryptsec", "key": "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p", "password": "wrong password!!", "relays": RELAYS}, tok)[0] == 400)
    check("still no config written", not os.path.exists(os.path.join(home, ".config/nak/bunker/default")))

    code, _ = post("/api/setup", {"mode": "generate", "password": PW, "relays": RELAYS}, tok)
    check("setup (generate) accepted", code == 200)
    cfg = json.load(open(os.path.join(home, ".config/nak/bunker/default")))
    check("config holds only an encrypted key", cfg["sec"].startswith("ncryptsec1"))
    check("config file mode 600", oct(os.stat(os.path.join(home, ".config/nak/bunker/default")).st_mode & 0o777) == "0o600")
    s = wait(lambda s: s["state"] == "running" and s["bunker_uri"], 90)
    check("nak unlocked and running", s["state"] == "running", s["state"] + " " + s["message"])
    check("bunker URI shown", bool(s["bunker_uri"]))
    ok_relays = [r for r, st in s["relay_status"].items() if st == "ok"]
    check("at least 2 relays ok", len(ok_relays) >= 2, str(s["relay_status"]))
    logtext = json.dumps(s["log"])
    check("password never in log", PW not in logtext)
    check("no ncryptsec/nsec/secret value in log", not re.search(r"ncryptsec1[0-9a-z]{10}|nsec1[0-9a-z]{10}|secret=[A-Za-z0-9]{4}", logtext))

    r = client(s["bunker_uri"])
    check("real NIP-46 client: connect + get_public_key + sign_event", r.get("connect") == "ok" and r.get("signed") is True, str(r))
    pub = r.get("pubkey")
    s = wait(lambda s: len(s["clients"]) >= 1, 15)
    check("client persisted as authorised", len(s["clients"]) == 1)
    client_pk = s["clients"][0]["pubkey"] if s["clients"] else ""

    # nak dies -> shim restarts it and re-unlocks from memory
    nak_pid = int(subprocess.run(["pgrep", "-f", "-n", NAK + " bunker"], capture_output=True, text=True).stdout.split()[0])
    os.kill(nak_pid, signal.SIGKILL)
    s = wait(lambda s: s["state"] != "running", 15)
    s = wait(lambda s: s["state"] == "running", 90)
    check("nak killed -> restarted and unlocked unattended", s["state"] == "running", s["state"] + " " + s["message"])
    r = client(s["bunker_uri"].split("&secret=")[0], "noconnect")
    check("authorised client still works after restart", r.get("pubkey") == pub, str(r))

    # relay edit -> restart with new list
    code, _ = post("/api/relays", {"relays": RELAYS + "\nwss://relay.damus.io"}, tok)
    s = wait(lambda s: s["state"] == "running" and "wss://relay.damus.io" in s["relays"], 90)
    check("relay list edited and nak restarted", s["state"] == "running" and len(s["relays"]) == 4)
finally:
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=15)

# app restart: password is gone, wrong then right
p, tok = start_shim(home)
try:
    s = wait(lambda s: s["state"] == "locked", 30)
    check("after app restart: locked, waiting for password", s["state"] == "locked")
    post("/api/unlock", {"password": "not the password", "remember": "1"}, tok)
    s = wait(lambda s: "Wrong" in s["message"], 30)
    check("wrong password reported", "Wrong" in s["message"], s["message"])
    check("wrong password not remembered", s["remembered"] is False)
    post("/api/unlock", {"password": PW, "remember": ""}, tok)
    s = wait(lambda s: s["state"] == "running", 60)
    check("right password on retry unlocks", s["state"] == "running", s["state"] + " " + s["message"])
    check("remember off -> not kept in memory", s["remembered"] is False)
    check("passwords never in log", PW not in json.dumps(s["log"]) and "not the password" not in json.dumps(s["log"]))
    code, _ = post("/api/client/remove", {"pubkey": client_pk}, tok)
    s = wait(lambda s: len(s["clients"]) == 0, 20)
    check("client removed", code == 200 and len(s["clients"]) == 0)
finally:
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=15)
    leftover = subprocess.run(["pgrep", "-f", NAK + " bunker"], capture_output=True, text=True).stdout.strip()
    check("no nak process left behind", leftover == "", leftover)
    shutil.rmtree(home, ignore_errors=True)

print("\nALL E2E CHECKS PASSED" if FAILS == 0 else f"\n{FAILS} E2E CHECKS FAILED")
sys.exit(1 if FAILS else 0)
