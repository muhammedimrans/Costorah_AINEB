"""
Phase 6B RQ4: is policy-class pooling actually viable, or does P explode?

The whole architecture rests on P (distinct policy classes) staying small and
independent of N. If realistic enterprise policy produces P ~ N, then O(P)
collapses to O(N) and Phase 6's result is worthless.

Two things are measured, and the distinction between them is the finding:

  P_policy   distinct EffectivePolicy tuples over ALL dimensions the brief
             lists. This is what "A == B" means in the safety condition.
  P_network  distinct tuples over only the dimensions a network enforcement
             point can actually act on (destination set, ports, protocols,
             network zone). Everything else -- rate limit, time window, data
             classification -- is enforced per-request at L7 and does NOT
             need its own connection pool.

Agents are generated with enterprise structure (departments, agent types,
tenants), not independent random draws, because independent draws would
manufacture an explosion that does not occur in practice. Both are reported.
"""

import itertools
import json
import random
import sys

RESULTS = "/home/claude/p6b/results_policyclass.json"
random.seed(20260826)

# Dimensions the brief requires, with realistic enterprise cardinalities.
# network_enforceable marks the ones an L3/L4 device can act on.
DIMS = {
    "destination_set":    {"card": 12, "network_enforceable": True},
    "ports":              {"card": 4,  "network_enforceable": True},
    "protocol":           {"card": 3,  "network_enforceable": True},
    "network_zone":       {"card": 5,  "network_enforceable": True},
    "data_class":         {"card": 4,  "network_enforceable": False},
    "risk":               {"card": 3,  "network_enforceable": False},
    "time_window":        {"card": 3,  "network_enforceable": False},
    "tenant":             {"card": 20, "network_enforceable": True},
    "user_privilege":     {"card": 4,  "network_enforceable": False},
    "agent_privilege":    {"card": 4,  "network_enforceable": False},
    "runtime_posture":    {"card": 3,  "network_enforceable": False},
    "device_posture":     {"card": 3,  "network_enforceable": False},
    "geography":          {"card": 6,  "network_enforceable": True},
    "rate_limit":         {"card": 5,  "network_enforceable": False},
}

NET_DIMS = [d for d, v in DIMS.items() if v["network_enforceable"]]
ALL_DIMS = list(DIMS.keys())


def theoretical_max():
    p_all = 1
    p_net = 1
    for d, v in DIMS.items():
        p_all *= v["card"]
        if v["network_enforceable"]:
            p_net *= v["card"]
    return p_all, p_net


def gen_independent(n):
    """Worst case: every dimension drawn independently."""
    out = []
    for _ in range(n):
        out.append(tuple(random.randrange(DIMS[d]["card"]) for d in ALL_DIMS))
    return out


def gen_structured(n, n_templates=40):
    """
    Realistic case: agents are instantiated from a limited set of
    organisational templates (department x agent-type), with a small amount of
    per-agent deviation on the non-network dimensions only.
    """
    templates = []
    for _ in range(n_templates):
        templates.append({d: random.randrange(DIMS[d]["card"]) for d in ALL_DIMS})

    out = []
    for _ in range(n):
        t = dict(random.choice(templates))
        # 5% of agents deviate on one NON-network dimension (e.g. a bespoke
        # rate limit or a stricter data class) -- this is what real exception
        # handling looks like.
        if random.random() < 0.05:
            d = random.choice([x for x in ALL_DIMS
                               if not DIMS[x]["network_enforceable"]])
            t[d] = random.randrange(DIMS[d]["card"])
        out.append(tuple(t[d] for d in ALL_DIMS))
    return out


def gen_structured_with_net_exceptions(n, n_templates=40, exc=0.05):
    """
    The dangerous case: exceptions land on NETWORK dimensions too. This is
    what happens when an operator grants one agent access to one extra
    destination.
    """
    templates = []
    for _ in range(n_templates):
        templates.append({d: random.randrange(DIMS[d]["card"]) for d in ALL_DIMS})
    out = []
    for _ in range(n):
        t = dict(random.choice(templates))
        if random.random() < exc:
            d = random.choice(ALL_DIMS)
            t[d] = random.randrange(DIMS[d]["card"])
        out.append(tuple(t[d] for d in ALL_DIMS))
    return out


def count(agents):
    net_idx = [ALL_DIMS.index(d) for d in NET_DIMS]
    p_all = len({a for a in agents})
    p_net = len({tuple(a[i] for i in net_idx) for a in agents})
    return p_all, p_net


def main():
    tmax_all, tmax_net = theoretical_max()
    print(f"dimensions: {len(ALL_DIMS)} total, {len(NET_DIMS)} network-enforceable")
    print(f"theoretical max P_policy  = {tmax_all:,}")
    print(f"theoretical max P_network = {tmax_net:,}")

    res = {"theoretical_max_P_policy": tmax_all,
           "theoretical_max_P_network": tmax_net,
           "network_dims": NET_DIMS, "all_dims": ALL_DIMS,
           "scenarios": {}}

    scenarios = {
        "independent_random": gen_independent,
        "structured_templates": gen_structured,
        "structured_net_exceptions_5pct": gen_structured_with_net_exceptions,
    }

    for name, fn in scenarios.items():
        print(f"\n--- {name} ---")
        print(f"  {'N':>10} {'P_policy':>10} {'P_network':>10} "
              f"{'P_net/N':>9}  {'conns@P_net':>11}")
        rows = []
        for n in (1_000, 10_000, 100_000, 1_000_000):
            agents = fn(n)
            p_all, p_net = count(agents)
            rows.append({"N": n, "P_policy": p_all, "P_network": p_net,
                         "P_network_over_N": round(p_net / n, 6)})
            print(f"  {n:>10,} {p_all:>10,} {p_net:>10,} "
                  f"{p_net/n:>9.5f}  {p_net:>11,}")
        res["scenarios"][name] = rows

    # Exception-rate sensitivity on the network dimensions: how bad does it get?
    print(f"\n--- sensitivity: network-dimension exception rate (N=100,000) ---")
    print(f"  {'exc_rate':>9} {'P_network':>10} {'P_net/N':>9}")
    sens = []
    for exc in (0.0, 0.01, 0.05, 0.10, 0.25, 0.50, 1.0):
        agents = gen_structured_with_net_exceptions(100_000, exc=exc)
        p_all, p_net = count(agents)
        sens.append({"exception_rate": exc, "P_network": p_net,
                     "P_network_over_N": round(p_net / 100_000, 6)})
        print(f"  {exc:>9.2f} {p_net:>10,} {p_net/100_000:>9.5f}")
    res["network_exception_sensitivity_N100k"] = sens

    json.dump(res, open(RESULTS, "w"), indent=2)
    print(f"\n-> {RESULTS}")


if __name__ == "__main__":
    main()
