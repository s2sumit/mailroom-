import base64, hashlib, json, sys, time
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/"
PROFILE = "ga5-mailroom-action-gate/v2"
canon = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
sha = lambda o: hashlib.sha256(canon(o).encode()).hexdigest()

priv = Ed25519PrivateKey.generate()
pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
x = base64.urlsafe_b64encode(pub).decode().rstrip("=")

dossiers = [{"dossierId": "d1", "partition": "stable_core", "receivedAt": "2026-10-23T09:00:00Z",
             "mailbox": "support", "objective": "Handle this mail",
             "sources": [{"sourceId": "s1", "kind": "email", "provenance": "external",
                          "title": "Where is my order",
                          "lines": [{"lineId": "s1-l1", "text": "Hi, status of order ORD-1001? Thanks, sam@example.com"}]}]}]
eid = "test-" + str(int(time.time()))
req = {"profile": PROFILE, "operation": "propose", "evaluationId": eid,
       "receiptVerifier": {"algorithm": "Ed25519", "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x}},
       "dossiers": dossiers}

r1 = httpx.post(URL, json=req, timeout=120); print("propose:", r1.status_code)
r2 = httpx.post(URL, json=req, timeout=120)
assert r1.text == r2.text, "replay must be identical"
changed = dict(req, dossiers=[dict(dossiers[0], objective="changed")])
print("changed content (want 409):", httpx.post(URL, json=changed, timeout=120).status_code)
print("garbage (want 400):", httpx.post(URL, content=b"nope").status_code)

resp = r1.json(); digest = resp["inputDigest"]
def make_receipts(accepted=True, tamper=False):
    out = []
    for p in resp["proposals"]:
        rc = {"dossierId": p["dossierId"], "callId": p["callId"], "action": p["action"],
              "accepted": accepted, "receiptId": "nonce-" + p["dossierId"],
              "proposalDigest": sha({"dossierId": p["dossierId"], "callId": p["callId"],
                                     "action": p["action"], "target": p["target"],
                                     "payload": p["payload"], "evidence": sorted(p["evidence"])})}
        msg = canon({"profile": PROFILE, "evaluationId": eid, "inputDigest": digest, "receipt": rc})
        sig = priv.sign(msg.encode())
        if tamper: sig = bytes([sig[0] ^ 1]) + sig[1:]
        out.append(dict(rc, receiptSignature=base64.b64encode(sig).decode()))
    return out

def commit(receipts):
    return httpx.post(URL, json={"profile": PROFILE, "operation": "commit", "evaluationId": eid,
                                 "inputDigest": digest, "receipts": receipts}, timeout=60)
print("bad signature (want 400):", commit(make_receipts(tamper=True)).status_code)
good = commit(make_receipts(accepted=True)); print("good commit:", good.status_code)
print(json.dumps(good.json()["outcomes"], indent=1))