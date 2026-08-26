"""
Phase 3b: is de-multiplexing cost necessarily linear in principal count?

D3 measured amplification factor 1.0 -- one upstream connection per principal.
This tests the sub-linear candidate named in PHASE3_REPORT.md section 6 (R1):

    key the upstream connection by POLICY EQUIVALENCE CLASS, not by principal.

Principals that resolve to the same network-observable policy share a
connection. Connections become O(distinct policies) instead of O(principals).

The question is what that costs. Two properties are measured separately,
because they are NOT the same thing and the literature tends to conflate them:

    ENFORCEMENT CORRECTNESS -- does every principal on a 5-tuple receive the
                               verdict its policy demands?
    ATTRIBUTION GRANULARITY -- given a 5-tuple, can the enforcement point name
                               which principal produced a given packet?

E1  linear baseline        -- key by principal (the D2 architecture)
E2  policy-class pooling   -- key by policy class
E3  scaling curve          -- connections vs principals, both schemes
E4  attribution loss       -- what audit fidelity is surrendered
"""

import json
import os
import socket
import threading
import time

RESULTS = "/home/claude/exp3/results_eqclass.json"
PORT = 9701

# A realistic enterprise shape: many principals, few distinct network policies.
POLICY_CLASSES = ["ALLOW_ALL", "DENY_ALL", "RESTRICT_EGRESS", "READONLY"]


class Upstream(threading.Thread):
    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = port
        self.stop = threading.Event()
        self.conns = {}
        self.lock = threading.Lock()

    def run(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.port))
        srv.listen(1024)
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
                    c.sendall(b'{"ok":1}\n')
        finally:
            c.close()


def make_principals(n, n_classes):
    """n principals distributed across n_classes distinct policies."""
    return {f"agent{i}@corp": POLICY_CLASSES[i % n_classes] for i in range(n)}


def run_scheme(scheme, principals, up):
    """scheme: 'per_principal' | 'per_policy_class'"""
    up.conns.clear()
    pool = {}
    t0 = time.time()

    for p, policy in principals.items():
        key = p if scheme == "per_principal" else policy
        if key not in pool:
            s = socket.socket()
            s.connect(("127.0.0.1", PORT))
            pool[key] = s
        s = pool[key]
        s.sendall(json.dumps({"principal": p, "policy": policy}).encode() + b"\n")
        s.recv(4096)

    setup_ms = (time.time() - t0) * 1000
    time.sleep(0.5)
    obs = dict(up.conns)

    # The control plane installs one policy per upstream 5-tuple.
    lport_policy = {}
    for key, s in pool.items():
        lp = s.getsockname()[1]
        lport_policy[lp] = key if scheme == "per_policy_class" else principals[key]

    # --- enforcement correctness ---
    wrong = 0
    total = 0
    # --- attribution granularity ---
    ambiguous_5tuples = 0
    max_principals_per_5tuple = 0

    for lp, seen in obs.items():
        installed = lport_policy.get(lp)
        distinct = set(seen)
        max_principals_per_5tuple = max(max_principals_per_5tuple, len(distinct))
        if len(distinct) > 1:
            ambiguous_5tuples += 1
        for p in distinct:
            total += 1
            if principals[p] != installed:
                wrong += 1

    for s in pool.values():
        try:
            s.close()
        except OSError:
            pass

    return {
        "scheme": scheme,
        "principals": len(principals),
        "distinct_policies": len(set(principals.values())),
        "upstream_connections": len(pool),
        "amplification_vs_principals": round(len(pool) / len(principals), 4),
        "enforcement_wrong_verdicts": wrong,
        "enforcement_correct": wrong == 0,
        "attribution_ambiguous_5tuples": ambiguous_5tuples,
        "max_principals_per_5tuple": max_principals_per_5tuple,
        "attribution_exact": max_principals_per_5tuple <= 1,
        "setup_ms_total": round(setup_ms, 1),
        "setup_ms_per_principal": round(setup_ms / len(principals), 4),
    }


def main():
    up = Upstream(PORT)
    up.start()
    time.sleep(0.4)

    res = {"comparison": [], "scaling": []}

    # ---- E1 / E2: head-to-head at fixed size -------------------------
    print(f"\n{'=' * 74}\n[E1/E2] per-principal vs policy-class pooling "
          f"(200 principals, 4 policies)\n{'=' * 74}")
    principals = make_principals(200, 4)
    for scheme in ("per_principal", "per_policy_class"):
        r = run_scheme(scheme, principals, up)
        res["comparison"].append(r)
        print(f"  {scheme:<18} conns={r['upstream_connections']:>4}  "
              f"amp={r['amplification_vs_principals']:<7} "
              f"enforce_ok={str(r['enforcement_correct']):<5} "
              f"attrib_exact={str(r['attribution_exact']):<5} "
              f"max_princ/5tuple={r['max_principals_per_5tuple']}")
        time.sleep(0.4)

    # ---- E3: scaling curve -------------------------------------------
    print(f"\n{'=' * 74}\n[E3] scaling: connections vs principal count "
          f"(4 policy classes)\n{'=' * 74}")
    print(f"  {'N':>6} {'per-principal':>15} {'per-policy-class':>18} "
          f"{'reduction':>11}")
    for n in (10, 50, 200, 800):
        ps = make_principals(n, 4)
        a = run_scheme("per_principal", ps, up)
        time.sleep(0.3)
        b = run_scheme("per_policy_class", ps, up)
        time.sleep(0.3)
        red = f"{a['upstream_connections'] / b['upstream_connections']:.0f}x"
        res["scaling"].append({"n": n, "per_principal": a, "per_policy_class": b,
                               "reduction": red})
        print(f"  {n:>6} {a['upstream_connections']:>15} "
              f"{b['upstream_connections']:>18} {red:>11}")

    # ---- E4: what attribution is surrendered -------------------------
    print(f"\n{'=' * 74}\n[E4] attribution surrendered by policy-class pooling\n{'=' * 74}")
    big = res["scaling"][-1]
    e4 = {
        "principals": big["n"],
        "per_principal_max_on_one_5tuple": big["per_principal"]["max_principals_per_5tuple"],
        "per_policy_class_max_on_one_5tuple": big["per_policy_class"]["max_principals_per_5tuple"],
        "enforcement_preserved": big["per_policy_class"]["enforcement_correct"],
        "attribution_preserved": big["per_policy_class"]["attribution_exact"],
    }
    print(f"  at {big['n']} principals / 4 policy classes:")
    print(f"    enforcement correctness preserved : {e4['enforcement_preserved']}")
    print(f"    per-principal attribution preserved: {e4['attribution_preserved']}")
    print(f"    principals indistinguishable on one 5-tuple: "
          f"{e4['per_policy_class_max_on_one_5tuple']}")
    print(f"\n  -> policy-class pooling keeps ENFORCEMENT and loses ATTRIBUTION.")
    print(f"     Network-layer audit degrades from 'which agent' to "
          f"'which policy class'.")
    res["E4_attribution_loss"] = e4

    up.stop.set()
    time.sleep(0.5)
    with open(RESULTS, "w") as f:
        json.dump(res, f, indent=2)
    print(f"\nresults -> {RESULTS}")


if __name__ == "__main__":
    main()
