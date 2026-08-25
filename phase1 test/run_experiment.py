"""
Phase 1: Co-Resident Agent Experiment.

E1  Selector collision      -- can SPIRE distinguish co-resident identical agents?
E2  Discriminator inventory -- which per-process facts vary, are unforgeable,
                               AND are admissible in a registration entry?
E3  Flow attribution        -- can a flow be attributed to an instance?
E4  Adversarial             -- can instance A obtain instance B's identity?
"""

import json
import os
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import attestor
import probes
import workload_api

DEST_PORT = 9443
N_AGENTS = 4
REPORT_DIR = "/tmp/agent-reports"
RESULTS = "/home/claude/exp/results.json"

PRINCIPALS = {
    "A": "alice@corp.example",
    "B": "bob@corp.example",
    "C": "carol@corp.example",
    "D": "dave@corp.example",
}


# --------------------------------------------------------------------------
# destination service (stands in for "the protected resource")
# --------------------------------------------------------------------------

def dest_server(stop_evt, seen):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", DEST_PORT))
    srv.listen(64)
    srv.settimeout(0.5)
    conns = []

    def handle(c, peer):
        buf = b""
        try:
            while not buf.endswith(b"\n"):
                ch = c.recv(4096)
                if not ch:
                    return
                buf += ch
            seen.append({"peer": peer, "payload": json.loads(buf.decode())})
            while not stop_evt.is_set():
                time.sleep(0.2)
        except Exception:
            pass

    while not stop_evt.is_set():
        try:
            c, peer = srv.accept()
        except socket.timeout:
            continue
        conns.append(c)
        threading.Thread(target=handle, args=(c, peer), daemon=True).start()
    for c in conns:
        try:
            c.close()
        except Exception:
            pass
    srv.close()


# --------------------------------------------------------------------------

def spawn_agents(strict_argv):
    """
    strict_argv=True  -> every instance has byte-identical argv (worst case)
    strict_argv=False -> instances differ only in an argv/env label
                         (the realistic case, and the one operators assume works)
    """
    procs = {}
    for label, principal in list(PRINCIPALS.items())[:N_AGENTS]:
        env = dict(os.environ)
        env["AGENT_PRINCIPAL"] = principal
        env["AGENT_LABEL"] = label
        env["AGENT_DEST_PORT"] = str(DEST_PORT)
        env["AGENT_HOLD"] = "14"
        argv = [sys.executable, os.path.join(HERE, "agent.py")]
        if not strict_argv:
            argv += ["--principal", principal]
        p = subprocess.Popen(argv, env=env, cwd=HERE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        procs[label] = p
    return procs


def run_condition(name, strict_argv, results):
    print(f"\n{'=' * 74}\nCONDITION: {name}\n{'=' * 74}")

    for f in list(os.listdir(REPORT_DIR)) if os.path.isdir(REPORT_DIR) else []:
        os.unlink(os.path.join(REPORT_DIR, f))

    stop = threading.Event()
    ready = threading.Event()
    seen = []

    t_dest = threading.Thread(target=dest_server, args=(stop, seen), daemon=True)
    t_dest.start()
    time.sleep(0.3)

    # Author the registration entry from a reference instance, before the
    # agents under test exist -- exactly the real operator workflow.
    ref = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(6)"],
                           cwd=HERE, stdout=subprocess.DEVNULL)
    time.sleep(0.4)
    workload_api.REGISTRATION_ENTRIES = workload_api.build_registration_entries(ref.pid)
    print(f"registration entry authored from reference PID {ref.pid}")
    print(f"  spiffe_id : {workload_api.REGISTRATION_ENTRIES[0]['spiffe_id']}")
    print(f"  selectors : {len(workload_api.REGISTRATION_ENTRIES[0]['selectors'])} attributes")

    t_api = threading.Thread(target=workload_api.serve, args=(ready, stop), daemon=True)
    t_api.start()
    ready.wait(5)

    procs = spawn_agents(strict_argv)
    time.sleep(2.5)

    live = {l: p.pid for l, p in procs.items() if p.poll() is None}
    if len(live) < N_AGENTS:
        for l, p in procs.items():
            if p.poll() is not None:
                print("  agent died:", l, p.stderr.read().decode()[:400])

    # ---------------- E1: selector collision -----------------------------
    sel = {l: attestor.attest(pid) for l, pid in live.items()}
    groups = {}
    for l, s in sel.items():
        groups.setdefault(json.dumps(s), []).append(l)

    e1 = {
        "instances": len(live),
        "distinct_selector_sets": len(groups),
        "collision_groups": [sorted(v) for v in groups.values()],
        "selector_set_example": sel[sorted(live)[0]] if live else [],
    }
    print(f"\n[E1] {len(live)} co-resident instances -> "
          f"{len(groups)} distinct SPIRE selector set(s)")
    for k, v in groups.items():
        print(f"     indistinguishable group: {sorted(v)}")

    # what the Workload API actually handed back
    svids = {}
    for l in sorted(live):
        rp = os.path.join(REPORT_DIR, f"{l}.json")
        if os.path.exists(rp):
            with open(rp) as f:
                svids[l] = json.load(f)
    e1["svids_issued"] = {l: r["svid_returned"]["spiffe_id"] for l, r in svids.items()}
    e1["peercred_pids"] = {l: r["svid_returned"]["peercred_pid"] for l, r in svids.items()}
    print(f"     SVIDs issued: {json.dumps(e1['svids_issued'])}")
    print(f"     SO_PEERCRED saw distinct PIDs: {json.dumps(e1['peercred_pids'])}")

    # ---------------- E2: discriminator inventory ------------------------
    allfacts = {l: probes.facts(pid) for l, pid in live.items()}
    keys = sorted(allfacts[sorted(live)[0]].keys()) if live else []
    inventory = []
    for k in keys:
        vals = {allfacts[l].get(k) for l in live}
        varies = len(vals) > 1
        mutable = k in probes.MUTABLE_BY_WORKLOAD
        predictable = k in probes.PREDICTABLE_PRE_REGISTRATION
        inventory.append({
            "fact": k,
            "varies_across_instances": varies,
            "kernel_authoritative": not mutable,
            "admissible_in_registration_entry": predictable,
            "usable_as_instance_selector": varies and (not mutable) and predictable,
        })

    usable = [i["fact"] for i in inventory if i["usable_as_instance_selector"]]
    e2 = {"inventory": inventory, "usable_instance_selectors": usable}
    print(f"\n[E2] facts examined: {len(inventory)}")
    print(f"     vary across instances          : "
          f"{[i['fact'] for i in inventory if i['varies_across_instances']]}")
    print(f"     vary AND kernel-authoritative  : "
          f"{[i['fact'] for i in inventory if i['varies_across_instances'] and i['kernel_authoritative']]}")
    print(f"     ...AND registration-admissible : {usable}")

    # ---------------- E3: flow attribution -------------------------------
    flows = probes.resolve_flows(want_rport=DEST_PORT)
    pid2label = {pid: l for l, pid in live.items()}
    attributed = []
    for fl in flows:
        labels = sorted({pid2label[p] for p in fl["pids"] if p in pid2label})
        attributed.append({**fl, "labels": labels})

    agent_flows = [a for a in attributed if a["labels"]]
    e3 = {
        "flows_to_destination": len(attributed),
        "attributable_via_proc_inode": len(agent_flows),
        "source_ips": sorted({a["laddr"] for a in attributed}),
        "flows": attributed,
        "claims_seen_by_destination": seen,
    }
    print(f"\n[E3] established flows to destination: {len(attributed)}")
    print(f"     distinct source IPs           : {e3['source_ips']}")
    print(f"     attributable to a PID locally : {len(agent_flows)}/{len(attributed)}")
    for a in agent_flows:
        print(f"       {a['laddr']}:{a['lport']} -> :{a['rport']}  "
              f"inode={a['inode']}  pid={a['pids']}  agent={a['labels']}")

    # ---------------- E4: adversarial ------------------------------------
    # A: does the destination get anything but a self-asserted claim?
    # B: can one instance present as another by editing what it controls?
    forged = None
    if not strict_argv and live:
        victim = sorted(live)[1]
        env = dict(os.environ)
        env["AGENT_PRINCIPAL"] = PRINCIPALS[victim]      # claim someone else's principal
        env["AGENT_LABEL"] = "IMPOSTOR"
        env["AGENT_DEST_PORT"] = str(DEST_PORT)
        env["AGENT_HOLD"] = "3"
        p = subprocess.Popen([sys.executable, os.path.join(HERE, "agent.py"),
                              "--principal", PRINCIPALS[victim]],
                             env=env, cwd=HERE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2.0)
        rp = os.path.join(REPORT_DIR, "IMPOSTOR.json")
        if os.path.exists(rp):
            with open(rp) as f:
                r = json.load(f)
            forged = {
                "impersonated": victim,
                "claimed_principal": PRINCIPALS[victim],
                "svid_issued": r["svid_returned"]["spiffe_id"],
                "selectors_identical_to_victim":
                    r["svid_returned"]["selectors"] == sel.get(victim),
            }
        p.wait(timeout=8)

    e4 = {
        "destination_sees_only_self_asserted_claims": True,
        "impersonation": forged,
    }
    print("\n[E4] adversarial")
    if forged:
        print(f"     impostor claimed  : {forged['claimed_principal']}")
        print(f"     SVID issued to it : {forged['svid_issued']}")
        print(f"     selector set identical to victim: "
              f"{forged['selectors_identical_to_victim']}")

    stop.set()
    for p in procs.values():
        try:
            p.wait(timeout=20)
        except Exception:
            p.kill()
    try:
        ref.wait(timeout=8)
    except Exception:
        ref.kill()
    time.sleep(0.6)

    results[name] = {"E1": e1, "E2": e2, "E3": e3, "E4": e4}


def main():
    os.makedirs(REPORT_DIR, exist_ok=True)
    results = {}
    run_condition("strict_identical_argv", True, results)
    run_condition("differ_by_label_only", False, results)
    with open(RESULTS, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nresults -> {RESULTS}")


if __name__ == "__main__":
    main()
