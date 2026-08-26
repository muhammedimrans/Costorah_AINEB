"""
Phase 4 RQ5 / claim C6: under policy-class pooling, how much per-principal
attribution can be recovered by correlating Envoy access logs with network
observations?

Method
------
Envoy pools upstream connections by POLICY CLASS. Many principals share each
connection. A network observer sees only the upstream 5-tuple and a byte
timing. We attempt to attribute each network event back to a principal using
only what Envoy logged: start time, duration, and UPSTREAM_LOCAL_ADDRESS
(which identifies the upstream connection by source port).

A network event at time T on connection C is EXACTLY ATTRIBUTED if precisely
one logged request on C has [start, start+duration] containing T. It is
AMBIGUOUS if more than one does.

The decisive variable is whether the upstream protocol multiplexes. HTTP/1.1
serialises requests on a connection; HTTP/2 does not.
"""

import json
import os
import subprocess
import sys
import threading
import time
import urllib.request

ACCESS_LOG = "/tmp/envoy_access.log"
GATEWAY = "http://127.0.0.1:10001"
RESULTS = "/home/claude/p4/results_attribution.json"


def fire(principal, path, n):
    for i in range(n):
        req = urllib.request.Request(f"{GATEWAY}{path}",
                                     headers={"x-agent-principal": principal})
        try:
            urllib.request.urlopen(req, timeout=10).read()
        except Exception:
            pass


def load_log():
    rows = []
    if not os.path.exists(ACCESS_LOG):
        return rows
    with open(ACCESS_LOG) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                start = float(r.get("ts") or 0)
                dur_ms = float(r.get("dur") or 0)
            except (TypeError, ValueError):
                continue
            conn = r.get("up_local") or "?"
            rows.append({
                "principal": r.get("principal"),
                "req_id": r.get("req_id"),
                "conn": conn,
                "start": start,
                "end": start + dur_ms / 1000.0,
                "cluster": r.get("cluster"),
            })
    return rows


def analyse(rows):
    """For every logged request, treat its midpoint as a network event and ask
    how many principals could have produced it on that connection."""
    by_conn = {}
    for r in rows:
        by_conn.setdefault(r["conn"], []).append(r)

    events = 0
    exact = 0
    ambiguous = 0
    max_overlap = 0
    conn_stats = {}

    for conn, reqs in by_conn.items():
        principals = sorted({r["principal"] for r in reqs if r["principal"]})
        overlaps_here = 0
        for r in reqs:
            t = (r["start"] + r["end"]) / 2.0
            # who else was in flight on this connection at time t?
            concurrent = [q for q in reqs if q["start"] <= t <= q["end"]]
            distinct = {q["principal"] for q in concurrent}
            events += 1
            if len(distinct) == 1:
                exact += 1
            else:
                ambiguous += 1
                overlaps_here += 1
            max_overlap = max(max_overlap, len(distinct))
        conn_stats[conn] = {
            "requests": len(reqs),
            "distinct_principals": len(principals),
            "ambiguous_events": overlaps_here,
        }

    return {
        "network_events": events,
        "exactly_attributed": exact,
        "ambiguous": ambiguous,
        "exact_attribution_rate": round(exact / events, 4) if events else None,
        "ambiguity_rate": round(ambiguous / events, 4) if events else None,
        "max_principals_concurrent_on_one_connection": max_overlap,
        "upstream_connections": len(by_conn),
        "connections": conn_stats,
    }


def audit_completeness(rows):
    """Fraction of requests whose log line carries the full chain."""
    need = ("principal", "req_id", "conn", "cluster")
    ok = sum(1 for r in rows if all(r.get(k) not in (None, "", "-", "?")
                                    for k in need))
    return {
        "requests": len(rows),
        "complete_records": ok,
        "audit_completeness": round(ok / len(rows), 4) if rows else None,
        "fields_checked": list(need),
    }


def run(label, concurrency, principals, reqs_each):
    print(f"\n--- {label}: {len(principals)} principals, "
          f"concurrency={concurrency} ---")
    open(ACCESS_LOG, "w").close()
    time.sleep(0.3)

    threads = []
    for p in principals:
        for _ in range(concurrency):
            t = threading.Thread(target=fire, args=(p, "/v1/tool", reqs_each))
            threads.append(t)
    t0 = time.time()
    [t.start() for t in threads]
    [t.join() for t in threads]
    wall = time.time() - t0
    time.sleep(1.5)

    rows = load_log()
    a = analyse(rows)
    a["audit"] = audit_completeness(rows)
    a["wall_s"] = round(wall, 2)
    a["concurrency_per_principal"] = concurrency

    print(f"  logged requests            : {len(rows)}")
    print(f"  upstream connections       : {a['upstream_connections']}")
    print(f"  exact attribution rate     : {a['exact_attribution_rate']}")
    print(f"  ambiguity rate             : {a['ambiguity_rate']}")
    print(f"  max principals concurrent  : "
          f"{a['max_principals_concurrent_on_one_connection']}")
    print(f"  audit completeness         : {a['audit']['audit_completeness']}")
    return a


def main():
    principals = [f"agent{i}@corp" for i in range(8)]
    res = {}
    for conc in (1, 4, 16):
        res[f"concurrency_{conc}"] = run(f"HTTP/1.1 upstream", conc,
                                         principals, 6)
        time.sleep(1.0)
    with open(RESULTS, "w") as f:
        json.dump(res, f, indent=2)
    print(f"\nresults -> {RESULTS}")


if __name__ == "__main__":
    main()
