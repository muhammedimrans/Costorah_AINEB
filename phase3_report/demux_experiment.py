"""
Phase 3: is the L7 -> L3/L4 translation problem real, or can it be dissolved?

The brief asks for: Alice -> ALLOW, Bob -> DENY, Carol -> RESTRICT
"over the same underlying connection".

D1  baseline            -- shared upstream pool. Can a 5-tuple enforcer separate
                           the three principals? (expected: no)
D2  principal-keyed pool -- gateway verifies the per-request proof, then keys the
                           UPSTREAM connection by verified principal. Now can a
                           pure 5-tuple enforcer separate them? (this is what
                           Envoy already does with hashable shared filter state)
D3  cost                -- connection amplification, latency, fd cost as the
                           principal count grows
D4  SO_MARK channel     -- can the gateway stamp a per-principal fwmark on the
                           upstream socket, i.e. does an L7->L3 signal already
                           exist in the kernel?

The per-request proof here is an HMAC stand-in for a WIMSE WPT (which uses
ES256/EdDSA proof-of-possession). The signature algorithm is irrelevant to what
is being measured: what matters is that the principal is only knowable after
parsing and verifying an application-layer object.
"""

import hashlib
import hmac
import json
import os
import socket
import struct
import threading
import time

RESULTS = "/home/claude/exp3/results_demux.json"
UPSTREAM_PORT = 9601
SO_MARK = 36

PRINCIPALS = {
    "alice@corp": {"key": b"k-alice", "policy": "ALLOW"},
    "bob@corp":   {"key": b"k-bob",   "policy": "DENY"},
    "carol@corp": {"key": b"k-carol", "policy": "RESTRICT"},
}
MARKS = {"alice@corp": 0xA1, "bob@corp": 0xB0, "carol@corp": 0xC2}


# ---------------------------------------------------------------- proof
def make_proof(principal, method, path, nonce):
    """Stand-in for a WPT: binds the principal to this specific request."""
    key = PRINCIPALS[principal]["key"]
    msg = f"{method}|{path}|{nonce}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_proof(principal, method, path, nonce, sig):
    if principal not in PRINCIPALS:
        return False
    return hmac.compare_digest(make_proof(principal, method, path, nonce), sig)


# ---------------------------------------------------------------- upstream
class Upstream(threading.Thread):
    """The protected resource. Records, per accepted connection, the 5-tuple and
    every principal that appeared on it."""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = port
        self.stop = threading.Event()
        self.conns = {}          # server-side peer port -> [principals]
        self.lock = threading.Lock()

    def run(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.port))
        srv.listen(256)
        srv.settimeout(0.5)
        while not self.stop.is_set():
            try:
                c, peer = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self.handle, args=(c, peer), daemon=True).start()
        srv.close()

    def handle(self, c, peer):
        c.settimeout(6)
        buf = b""
        try:
            while not self.stop.is_set():
                try:
                    d = c.recv(65536)
                except (socket.timeout, OSError):
                    break
                if not d:
                    break
                buf += d
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    req = json.loads(line)
                    with self.lock:
                        self.conns.setdefault(peer[1], []).append(req["principal"])
                    c.sendall(b'{"ok":true}\n')
        finally:
            c.close()


# ---------------------------------------------------------------- gateway
class Gateway:
    """
    L7 verifier + connection manager.

    mode='shared'    : one upstream connection, all principals multiplexed onto it
    mode='per_principal': upstream connection keyed by VERIFIED principal
    """

    def __init__(self, mode, upstream_port, use_mark=False):
        self.mode = mode
        self.port = upstream_port
        self.use_mark = use_mark
        self.pool = {}
        self.lock = threading.Lock()
        self.rejected = []

    def _new_conn(self, principal):
        s = socket.socket()
        if self.use_mark and principal in MARKS:
            # The L7 verdict, stamped onto the socket for the kernel to see.
            s.setsockopt(socket.SOL_SOCKET, SO_MARK, MARKS[principal])
        s.connect(("127.0.0.1", self.port))
        return s

    def _get_conn(self, principal):
        key = "shared" if self.mode == "shared" else principal
        with self.lock:
            if key not in self.pool:
                self.pool[key] = self._new_conn(principal)
            return self.pool[key]

    def handle(self, principal, method, path, nonce, sig):
        # 1. verify the application-layer proof
        if not verify_proof(principal, method, path, nonce, sig):
            self.rejected.append(principal)
            return {"error": "bad proof"}
        # 2. select / create upstream connection
        s = self._get_conn(principal)
        lport = s.getsockname()[1]
        mark = None
        if self.use_mark:
            mark = s.getsockopt(socket.SOL_SOCKET, SO_MARK)
        s.sendall(json.dumps({"principal": principal, "path": path}).encode() + b"\n")
        s.recv(4096)
        return {"lport": lport, "mark": mark}

    def close(self):
        for s in self.pool.values():
            try:
                s.close()
            except OSError:
                pass


# ---------------------------------------------------------------- L3/L4 enforcer
def l4_enforce(observations, policy_by_lport):
    """
    A pure 5-tuple enforcement point. It sees ONLY source port -> policy mapping
    that some control plane installed. It cannot parse anything above L4.
    Returns whether it can render a correct per-principal verdict.
    """
    verdicts = {}
    for lport, principals in observations.items():
        distinct = sorted(set(principals))
        policy = policy_by_lport.get(lport)
        verdicts[lport] = {
            "principals_on_this_5tuple": distinct,
            "installed_policy": policy,
            "unambiguous": len(distinct) == 1,
            "correct": len(distinct) == 1
                       and policy == PRINCIPALS[distinct[0]]["policy"],
        }
    return verdicts


# ---------------------------------------------------------------- D1 / D2
def run_condition(name, mode, use_mark, up):
    print(f"\n{'=' * 74}\n[{name}] gateway mode = {mode}\n{'=' * 74}")
    up.conns.clear()
    gw = Gateway(mode, UPSTREAM_PORT, use_mark=use_mark)

    lport_of = {}
    marks = {}
    for i in range(4):
        for p in PRINCIPALS:
            nonce = f"{p}-{i}"
            sig = make_proof(p, "POST", "/v1/tool", nonce)
            r = gw.handle(p, "POST", "/v1/tool", nonce, sig)
            lport_of.setdefault(p, set()).add(r["lport"])
            if r.get("mark") is not None:
                marks[p] = r["mark"]

    time.sleep(0.6)
    obs = dict(up.conns)

    # The control plane installs one policy per upstream 5-tuple, derived from
    # the verified L7 identity that owns it.
    policy_by_lport = {}
    for p, ports in lport_of.items():
        for lp in ports:
            policy_by_lport[lp] = PRINCIPALS[p]["policy"]

    verdicts = l4_enforce(obs, policy_by_lport)
    n_conns = len(obs)
    ambiguous = [v for v in verdicts.values() if not v["unambiguous"]]
    correct = [v for v in verdicts.values() if v["correct"]]

    print(f"  principals                      : {len(PRINCIPALS)}")
    print(f"  upstream connections created    : {n_conns}")
    for lp, v in sorted(verdicts.items()):
        print(f"    5-tuple :{lp:<6} principals={v['principals_on_this_5tuple']}"
              f"  policy={v['installed_policy']}  ok={v['correct']}")
    print(f"  ambiguous 5-tuples              : {len(ambiguous)}")
    print(f"  L4-only enforcement CORRECT     : "
          f"{len(correct)}/{len(verdicts)}"
          f"  -> {'SUFFICIENT' if not ambiguous else 'INSUFFICIENT'}")
    if marks:
        print(f"  SO_MARK per principal           : "
              f"{ {k: hex(v) for k, v in marks.items()} }")

    gw.close()
    return {
        "mode": mode,
        "principals": len(PRINCIPALS),
        "upstream_connections": n_conns,
        "verdicts": {str(k): v for k, v in verdicts.items()},
        "ambiguous_5tuples": len(ambiguous),
        "l4_only_enforcement_sufficient": len(ambiguous) == 0,
        "socket_marks": {k: hex(v) for k, v in marks.items()} if marks else None,
    }


# ---------------------------------------------------------------- D3
def d3_cost(up):
    print(f"\n{'=' * 74}\n[D3] cost of de-multiplexing as principal count grows\n{'=' * 74}")
    rows = []
    for n in (1, 10, 100, 500):
        # synthesise n principals
        keys = {f"p{i}@corp": {"key": f"k{i}".encode(), "policy": "ALLOW"}
                for i in range(n)}
        PRINCIPALS.update(keys)
        gw = Gateway("per_principal", UPSTREAM_PORT)
        fd_before = len(os.listdir("/proc/self/fd"))
        t0 = time.time()
        for p in keys:
            nonce = "x"
            sig = make_proof(p, "POST", "/v1/tool", nonce)
            gw.handle(p, "POST", "/v1/tool", nonce, sig)
        dt = time.time() - t0
        fd_after = len(os.listdir("/proc/self/fd"))
        rows.append({
            "principals": n,
            "upstream_connections": len(gw.pool),
            "amplification": len(gw.pool) / 1.0,
            "fds_consumed": fd_after - fd_before,
            "setup_ms_total": round(dt * 1000, 1),
            "setup_ms_per_principal": round(dt * 1000 / n, 3),
        })
        print(f"  {n:>4} principals -> {len(gw.pool):>4} upstream conns, "
              f"{fd_after - fd_before:>4} fds, "
              f"{dt * 1000 / n:.3f} ms/principal setup")
        gw.close()
        for k in keys:
            PRINCIPALS.pop(k, None)
        time.sleep(0.3)
    return rows


# ---------------------------------------------------------------- D4
def d4_mark_channel():
    print(f"\n{'=' * 74}\n[D4] SO_MARK as an existing L7 -> L3 signalling channel\n{'=' * 74}")
    out = {}
    s = socket.socket()
    try:
        s.setsockopt(socket.SOL_SOCKET, SO_MARK, 0xA1)
        got = s.getsockopt(socket.SOL_SOCKET, SO_MARK)
        out["so_mark_settable"] = True
        out["so_mark_readback"] = hex(got)
        print(f"  SO_MARK settable by userspace   : True (read back {hex(got)})")
    except OSError as e:
        out["so_mark_settable"] = False
        out["error"] = str(e)
        print(f"  SO_MARK settable                : False ({e})")
    out["requires_cap_net_admin"] = True
    out["mark_width_bits"] = 32
    out["visible_to"] = ["nftables/iptables meta mark", "policy routing (ip rule fwmark)",
                         "tc filters", "eBPF via sk->mark"]
    out["crosses_host_boundary"] = False
    print(f"  requires CAP_NET_ADMIN          : True")
    print(f"  mark width                      : 32 bits")
    print(f"  survives off-host               : False  <- local-only channel")
    s.close()
    return out


def main():
    os.makedirs("/home/claude/exp3", exist_ok=True)
    up = Upstream(UPSTREAM_PORT)
    up.start()
    time.sleep(0.4)

    res = {}
    res["D1_shared_pool"] = run_condition("D1", "shared", False, up)
    res["D2_principal_keyed_pool"] = run_condition("D2", "per_principal", True, up)
    res["D3_cost"] = d3_cost(up)
    res["D4_so_mark"] = d4_mark_channel()

    up.stop.set()
    time.sleep(0.5)
    with open(RESULTS, "w") as f:
        json.dump(res, f, indent=2)
    print(f"\nresults -> {RESULTS}")


if __name__ == "__main__":
    main()
