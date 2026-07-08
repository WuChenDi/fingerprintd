#!/usr/bin/env python3
"""End-to-end verify of the deployed fingerprintd edge Worker (T8 probe + T9 signing).

Run with the SAME secret values you set on the Worker:

    FP_PROBE_KEY=... FP_SIGNING_KEY=... python3 /tmp/verify-deploy.py

Optional: FP_ENFORCE_TS_WINDOW=1 also exercises the timestamp window (T9).
Secrets stay in your shell env; they are never printed.
"""
import hmac, hashlib, json, os, struct, sys, urllib.request

BASE = os.environ.get("BASE", "https://fingerprintd-edge.cdlab.workers.dev")
PROBE_KEY = os.environ.get("FP_PROBE_KEY", "").encode()
SIGNING_KEY = os.environ.get("FP_SIGNING_KEY", "").encode()
TS_WINDOW = os.environ.get("FP_ENFORCE_TS_WINDOW", "").lower() in ("1", "true", "yes")

COMPONENTS = {"userAgent": "UA", "languages": "en", "timezone": "UTC", "platform": "Linux"}
ok = True

def check(name, cond, extra=""):
    global ok
    ok = ok and cond
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{('  '+extra) if extra else ''}")

def challenge():
    with urllib.request.urlopen(f"{BASE}/challenge") as r:
        return json.load(r)["nonce"]

def hmac_hex(key, msg):
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

def identify(nonce, probe=None, ts=None):
    body = {"nonce": nonce, "stable_components": COMPONENTS}
    if probe is not None: body["probe"] = probe
    if ts is not None: body["ts"] = ts
    data = json.dumps(body).encode()
    req = urllib.request.Request(f"{BASE}/identify", data=data,
                                 headers={"content-type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()

print(f"BASE={BASE}")
if not PROBE_KEY or not SIGNING_KEY:
    print("!! set FP_PROBE_KEY and FP_SIGNING_KEY in env first"); sys.exit(2)

# --- T8: correct probe is accepted -----------------------------------------
print("\n== T8 probe accept ==")
n = challenge()
probe = hmac_hex(PROBE_KEY, n.encode())
status, headers, body = identify(n, probe=probe, ts=(_now := __import__("time").time_ns() // 1_000_000) if TS_WINDOW else None)
check("correct probe -> 200", status == 200, f"got {status}")
resp = json.loads(body) if status == 200 else {}
check("body has visitorId", "visitorId" in resp, resp.get("visitorId", "")[:16] + "...")

# --- T9: response is signed over the exact bytes ----------------------------
print("\n== T9 signing ==")
ts_hdr = headers.get("x-fp-timestamp")
sig_hdr = headers.get("x-fp-signature")
check("x-fp-timestamp present", ts_hdr is not None, str(ts_hdr))
check("x-fp-signature present", sig_hdr is not None)
if ts_hdr and sig_hdr:
    expect = hmac_hex(SIGNING_KEY, struct.pack(">Q", int(ts_hdr)) + body)
    check("signature matches HMAC(signing_key, be(ts)++body)",
          hmac.compare_digest(expect, sig_hdr))

# --- T9: timestamp window (only if enabled) ---------------------------------
if TS_WINDOW:
    print("\n== T9 timestamp window ==")
    n = challenge()
    stale = (_now - 3_600_000)  # 1h in the past
    status, _, _ = identify(n, probe=hmac_hex(PROBE_KEY, n.encode()), ts=stale)
    check("stale ts -> 401", status == 401, f"got {status}")

print("\n" + ("ALL PASS" if ok else "SOME FAILED"))
sys.exit(0 if ok else 1)
