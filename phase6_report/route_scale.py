"""
Phase 6 E1: does the Phase 5 architecture actually scale?

Phase 5 routed on x-verified-principal with one exact-match route per
principal. That is O(N) route entries. At a million agents that is a million
routes in every gateway's config.

The alternative: have the identity service emit a signed POLICY CLASS claim,
and route on that. Route entries become O(P).

Measures, for both schemes at increasing N:
    generated config size
    Envoy startup / config load time
    resident memory after load
    request latency (p50/p99)
"""

import json
import os
import resource
import subprocess
import sys
import time
import urllib.request

OUT = "/home/claude/p6/results_routescale.json"
ADMIN = 19902
LISTEN = 10001
UPSTREAM = 19002


def gen_per_principal(n, path):
    """One exact-match route per principal: O(N)."""
    routes = []
    for i in range(n):
        cls = "allow" if i % 2 == 0 else "restrict"
        routes.append(
            '              - match: {prefix: "/", headers: [{name: '
            'x-verified-principal, string_match: {exact: "agent%d@corp"}}]}\n'
            "                route: {cluster: c_%s}" % (i, cls))
    routes.append('              - match: {prefix: "/"}\n'
                  "                route: {cluster: c_allow}")
    return write(path, routes)


def gen_policy_class(n, path):
    """Route on a signed policy-class claim: O(P), independent of N."""
    routes = []
    for cls in ("allow", "restrict"):
        routes.append(
            '              - match: {prefix: "/", headers: [{name: '
            'x-policy-class, string_match: {exact: "%s"}}]}\n'
            "                route: {cluster: c_%s}" % (cls, cls))
    routes.append('              - match: {prefix: "/"}\n'
                  "                route: {cluster: c_allow}")
    return write(path, routes)


def write(path, routes):
    clusters = ""
    for c in ("allow", "restrict"):
        clusters += (
            "  - name: c_%s\n"
            "    connect_timeout: 2s\n"
            "    type: STATIC\n"
            "    load_assignment: {cluster_name: c_%s, endpoints: "
            "[{lb_endpoints: [{endpoint: {address: {socket_address: "
            "{address: 127.0.0.1, port_value: %d}}}}]}]}\n" % (c, c, UPSTREAM))
    cfg = f"""node: {{id: "gw", cluster: "gw"}}
admin: {{address: {{socket_address: {{address: 127.0.0.1, port_value: {ADMIN}}}}}}}
static_resources:
  listeners:
  - name: l
    address: {{socket_address: {{address: 127.0.0.1, port_value: {LISTEN}}}}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress
          route_config:
            name: r
            virtual_hosts:
            - name: v
              domains: ["*"]
              routes:
{chr(10).join(routes)}
          http_filters:
          - name: envoy.filters.http.router
            typed_config: {{"@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router}}
  clusters:
{clusters}"""
    with open(path, "w") as f:
        f.write(cfg)
    return os.path.getsize(path)


def rss_of(pid):
    try:
        for line in open(f"/proc/{pid}/status"):
            if line.startswith("VmRSS:"):
                return int(line.split()[1])  # kB
    except OSError:
        pass
    return None


def measure(cfg_path, header_name, header_value, label, n):
    subprocess.run(["pkill", "-x", "envoy"], capture_output=True)
    time.sleep(1.0)

    t0 = time.time()
    p = subprocess.Popen(["envoy", "-c", cfg_path, "--base-id", "41",
                          "--log-level", "error"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ready = None
    while time.time() - t0 < 180:
        try:
            r = urllib.request.urlopen(f"http://127.0.0.1:{ADMIN}/ready",
                                       timeout=2)
            if r.status == 200:
                ready = time.time() - t0
                break
        except Exception:
            time.sleep(0.25)
    if ready is None:
        p.kill()
        return {"scheme": label, "principals": n, "startup_s": None,
                "error": "did not become ready within 180s"}

    time.sleep(1.5)
    rss = rss_of(p.pid)

    lat = []
    for _ in range(400):
        t = time.perf_counter()
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{LISTEN}/v1/tool",
                                         headers={header_name: header_value})
            urllib.request.urlopen(req, timeout=10).read()
            lat.append(time.perf_counter() - t)
        except Exception:
            pass
    lat.sort()

    def q(f):
        return round(lat[int(len(lat) * f)] * 1000, 3) if lat else None

    res = {
        "scheme": label,
        "principals": n,
        "route_entries": (n + 1) if label == "per_principal" else 3,
        "config_bytes": os.path.getsize(cfg_path),
        "startup_s": round(ready, 2),
        "rss_kb": rss,
        "requests_ok": len(lat),
        "p50_ms": q(.50), "p99_ms": q(.99),
    }
    p.kill()
    time.sleep(0.6)
    return res


def main():
    os.makedirs("/home/claude/p6", exist_ok=True)
    rows = []
    for n in (1000, 10000, 100000):
        pp = f"/home/claude/p6/rt_pp_{n}.yaml"
        sz = gen_per_principal(n, pp)
        print(f"\n--- per-principal, N={n} (config {sz/1e6:.1f} MB) ---",
              flush=True)
        r = measure(pp, "x-verified-principal", f"agent{n//2}@corp",
                    "per_principal", n)
        print(f"    routes={r['route_entries']} startup={r.get('startup_s')}s "
              f"rss={r.get('rss_kb')}kB p50={r.get('p50_ms')}ms "
              f"p99={r.get('p99_ms')}ms {r.get('error','')}", flush=True)
        rows.append(r)
        os.unlink(pp)

        pc = f"/home/claude/p6/rt_pc_{n}.yaml"
        sz = gen_policy_class(n, pc)
        print(f"--- policy-class,  N={n} (config {sz} B) ---", flush=True)
        r = measure(pc, "x-policy-class", "allow", "policy_class", n)
        print(f"    routes={r['route_entries']} startup={r.get('startup_s')}s "
              f"rss={r.get('rss_kb')}kB p50={r.get('p50_ms')}ms "
              f"p99={r.get('p99_ms')}ms", flush=True)
        rows.append(r)
        os.unlink(pc)

    json.dump(rows, open(OUT, "w"), indent=2)
    print(f"\n-> {OUT}")


if __name__ == "__main__":
    main()
