"""
Phase 5 RQ2 / Test 5-7: real cryptographic agent identity at the gateway.

Implements an Envoy ext_authz HTTP service that verifies a WIMSE-WPT-shaped
proof-of-possession token. The token is a real EdDSA (Ed25519) JWT carrying the
full delegation chain the brief asks about:

    human (sub / act.human)
      -> agent   (agent_id, the workload)
        -> session (sid)
          -> credential (this signed token, bound to method+path, short TTL)

The gateway verifies the signature, the audience, the expiry, the replay
window (jti), and the binding to THIS request. Only then does it emit
x-verified-principal, which the route table matches on. Any client-supplied
x-agent-principal is discarded.

This is what replaces the trusted test header used in Phases 3-4B.
"""

import base64
import http.server
import json
import os
import threading
import time

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PORT = 19500
STATE = "/tmp/authz_state.json"

# --- agent keys: one Ed25519 keypair per agent workload -------------------
AGENTS = {}
for i in range(8):
    AGENTS[f"agent{i}"] = Ed25519PrivateKey.generate()

# The delegation table the enterprise would hold: which human authorized which
# agent, and what risk tier that pairing carries.
DELEGATION = {
    f"agent{i}": {
        "human": f"human{i}@corp.example",
        "principal": f"agent{i}@corp",
        "risk": "high" if i in (0, 1) else "normal",
    } for i in range(8)
}

seen_jti = {}
jti_lock = threading.Lock()
stats = {"allowed": 0, "denied": 0, "reasons": {}}
stats_lock = threading.Lock()


def priv_pem(agent):
    from cryptography.hazmat.primitives import serialization
    return AGENTS[agent].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())


def pub_pem(agent):
    from cryptography.hazmat.primitives import serialization
    return AGENTS[agent].public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)


def mint(agent, session_id, method, path, ttl=30, aud="upstream.agents.internal"):
    """Client side: mint a WPT-shaped proof bound to this request."""
    d = DELEGATION[agent]
    now = int(time.time())
    claims = {
        "iss": f"spiffe://corp.example/agent/{agent}",
        "sub": d["principal"],
        "aud": aud,
        "iat": now,
        "exp": now + ttl,
        "jti": base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip("="),
        "sid": session_id,
        "act": {"human": d["human"]},          # delegation chain
        "htm": method,                          # bound to this request
        "htu": path,
    }
    return jwt.encode(claims, priv_pem(agent), algorithm="EdDSA")


def note(reason):
    with stats_lock:
        stats["reasons"][reason] = stats["reasons"].get(reason, 0) + 1


def verify(token, method, path):
    if not token:
        return None, "missing_token"
    try:
        unverified = jwt.get_unverified_header(token)
        if unverified.get("alg") != "EdDSA":
            return None, "bad_alg"
        body = jwt.decode(token, options={"verify_signature": False})
        iss = body.get("iss", "")
        agent = iss.rsplit("/", 1)[-1]
        if agent not in AGENTS:
            return None, "unknown_agent"
    except Exception:
        return None, "malformed"

    try:
        claims = jwt.decode(token, pub_pem(agent), algorithms=["EdDSA"],
                            audience="upstream.agents.internal")
    except jwt.ExpiredSignatureError:
        return None, "expired"
    except jwt.InvalidSignatureError:
        return None, "bad_signature"
    except Exception as e:
        return None, f"invalid:{e.__class__.__name__}"

    if claims.get("htm") != method or claims.get("htu") != path:
        return None, "request_binding_mismatch"

    jti = claims.get("jti")
    with jti_lock:
        now = time.time()
        for k, v in list(seen_jti.items()):
            if v < now - 120:
                del seen_jti[k]
        if jti in seen_jti:
            return None, "replay"
        seen_jti[jti] = now

    d = DELEGATION[agent]
    if claims.get("sub") != d["principal"]:
        return None, "principal_mismatch"
    if claims.get("act", {}).get("human") != d["human"]:
        return None, "delegation_mismatch"

    return {
        "principal": d["principal"],
        "human": d["human"],
        "agent": agent,
        "session": claims.get("sid", ""),
        "risk": d["risk"],
    }, "ok"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _authz(self):
        token = self.headers.get("x-agent-wpt")
        method = self.headers.get("x-original-method", "POST")
        path = self.headers.get("x-original-path", "/v1/tool")
        ident, reason = verify(token, method, path)
        note(reason)
        if ident is None:
            with stats_lock:
                stats["denied"] += 1
            body = json.dumps({"denied": reason}).encode()
            self.send_response(403)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("x-deny-reason", reason)
            self.end_headers()
            self.wfile.write(body)
            return
        with stats_lock:
            stats["allowed"] += 1
        self.send_response(200)
        self.send_header("x-verified-principal", ident["principal"])
        self.send_header("x-verified-human", ident["human"])
        self.send_header("x-verified-agent", ident["agent"])
        self.send_header("x-verified-session", ident["session"])
        self.send_header("x-verified-risk", ident["risk"])
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path == "/__stats":
            with stats_lock:
                b = json.dumps(stats).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        self._authz()

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            if n:
                self.rfile.read(n)
        except (TypeError, ValueError):
            pass
        self._authz()


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    # publish minting material for the load generator
    import pickle
    with open("/tmp/agent_keys.pkl", "wb") as f:
        pickle.dump({a: priv_pem(a) for a in AGENTS}, f)
    with open("/tmp/delegation.json", "w") as f:
        json.dump(DELEGATION, f)
    print(f"ext_authz on :{PORT}", flush=True)
    Server(("127.0.0.1", PORT), Handler).serve_forever()
