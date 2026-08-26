"""
Phase 6: the two remaining capacity questions.

C1  Identity verification throughput. Every request needs an Ed25519 signature
    check. This sets agents-per-gateway-core.
C2  eBPF verdict map at a million entries: does it fit, how fast can the
    control plane load it, and does lookup stay flat?
"""

import ctypes
import json
import os
import resource
import statistics
import sys
import time

sys.path.insert(0, "/home/claude/p5")

RESULTS = "/home/claude/p6/results_capacity.json"


# ---------------------------------------------------------------- C1
def c1_crypto():
    import jwt
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
    pub = k.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)

    now = int(time.time())
    claims = {"iss": "spiffe://corp.example/agent/a1", "sub": "a1@corp",
              "aud": "upstream.agents.internal", "iat": now, "exp": now + 60,
              "jti": "x" * 16, "sid": "s1",
              "act": {"human": "h1@corp.example"},
              "htm": "POST", "htu": "/v1/tool"}
    tok = jwt.encode(claims, priv, algorithm="EdDSA")
    print(f"  token size: {len(tok)} bytes")

    # raw signature verify (the crypto floor)
    msg = b"x" * 128
    sig = k.sign(msg)
    pk = k.public_key()
    n = 20000
    t0 = time.perf_counter()
    for _ in range(n):
        pk.verify(sig, msg)
    raw = n / (time.perf_counter() - t0)

    # full JWT decode+verify (what the gateway actually does)
    n2 = 5000
    t0 = time.perf_counter()
    for _ in range(n2):
        jwt.decode(tok, pub, algorithms=["EdDSA"],
                   audience="upstream.agents.internal")
    full = n2 / (time.perf_counter() - t0)

    # per-call latency distribution
    lat = []
    for _ in range(3000):
        t = time.perf_counter()
        jwt.decode(tok, pub, algorithms=["EdDSA"],
                   audience="upstream.agents.internal")
        lat.append((time.perf_counter() - t) * 1e6)
    lat.sort()

    print(f"  raw Ed25519 verify    : {raw:,.0f} ops/s/core")
    print(f"  full JWT verify       : {full:,.0f} ops/s/core")
    print(f"  per-verify p50        : {lat[len(lat)//2]:.1f} us")
    print(f"  per-verify p99        : {lat[int(len(lat)*.99)]:.1f} us")
    return {
        "token_bytes": len(tok),
        "raw_ed25519_verify_per_s_per_core": round(raw),
        "full_jwt_verify_per_s_per_core": round(full),
        "p50_us": round(lat[len(lat) // 2], 1),
        "p99_us": round(lat[int(len(lat) * .99)], 1),
    }


# ---------------------------------------------------------------- C2
def c2_bpf_map():
    import bpfctl
    from bpfctl import lib, FlowKey, Verdict, BPF_ANY

    # Rebuild the object with a 1M-entry map.
    src = open("/home/claude/p5/enforce.bpf.c").read()
    src = src.replace("__uint(max_entries, 65536);",
                      "__uint(max_entries, 1048576);")
    open("/home/claude/p6/enforce_big.bpf.c", "w").write(src)
    rc = os.system("clang -O2 -g -target bpf -D__TARGET_ARCH_x86 "
                   "-c /home/claude/p6/enforce_big.bpf.c "
                   "-o /home/claude/p6/enforce_big.bpf.o 2>/dev/null")
    if rc != 0:
        return {"error": "compile failed"}

    obj = lib.bpf_object__open_file(b"/home/claude/p6/enforce_big.bpf.o", None)
    if not obj:
        return {"error": "open failed"}
    if lib.bpf_object__load(ctypes.c_void_p(obj)) != 0:
        return {"error": "load failed"}
    m = lib.bpf_object__find_map_by_name(ctypes.c_void_p(obj), b"verdicts")
    fd = lib.bpf_map__fd(ctypes.c_void_p(m))

    def meminfo():
        for line in open("/proc/meminfo"):
            if line.startswith("MemAvailable:"):
                return int(line.split()[1])
        return None

    rows = []
    inserted = 0
    before_mem = meminfo()
    for target in (1000, 10000, 100000, 1000000):
        t0 = time.perf_counter()
        while inserted < target:
            k = FlowKey(daddr=inserted & 0xFFFFFFFF,
                        dport=(inserted % 65535) or 1, pad=0)
            v = Verdict(action=1, principal_id=inserted, expires_ns=0, hits=0)
            if lib.bpf_map_update_elem(fd, ctypes.byref(k),
                                       ctypes.byref(v), BPF_ANY) != 0:
                break
            inserted += 1
        dt = time.perf_counter() - t0

        # lookup latency at this fill level
        lat = []
        for i in range(0, min(inserted, 5000)):
            idx = (i * 7919) % inserted
            k = FlowKey(daddr=idx & 0xFFFFFFFF,
                        dport=(idx % 65535) or 1, pad=0)
            v = Verdict()
            t = time.perf_counter()
            lib.bpf_map_lookup_elem(fd, ctypes.byref(k), ctypes.byref(v))
            lat.append((time.perf_counter() - t) * 1e6)
        lat.sort()
        after_mem = meminfo()
        row = {
            "entries": inserted,
            "load_s_cumulative": round(dt, 2),
            "lookup_p50_us": round(lat[len(lat) // 2], 2) if lat else None,
            "lookup_p99_us": round(lat[int(len(lat) * .99)], 2) if lat else None,
            "mem_consumed_kb": (before_mem - after_mem) if
                               (before_mem and after_mem) else None,
        }
        rows.append(row)
        print(f"  {inserted:>9,} entries  load+{dt:>6.2f}s  "
              f"lookup p50={row['lookup_p50_us']}us "
              f"p99={row['lookup_p99_us']}us  "
              f"mem={row['mem_consumed_kb']}kB")
        if inserted < target:
            print(f"    -> insert failed at {inserted:,}")
            break
    return {"rows": rows, "max_entries_configured": 1048576,
            "entries_inserted": inserted}


def main():
    os.makedirs("/home/claude/p6", exist_ok=True)
    print(f"\n{'='*74}\n[C1] identity verification throughput (single core)\n{'='*74}")
    c1 = c1_crypto()
    print(f"\n{'='*74}\n[C2] eBPF verdict map to 1,000,000 entries\n{'='*74}")
    c2 = c2_bpf_map()
    json.dump({"C1_crypto": c1, "C2_bpf_map": c2},
              open(RESULTS, "w"), indent=2)
    print(f"\n-> {RESULTS}")


if __name__ == "__main__":
    main()
