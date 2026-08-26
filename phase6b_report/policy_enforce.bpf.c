/* Phase 6B RQ9: what must the eBPF verdict map actually be keyed by?
 *
 * Phase 6 assumed destination-only keying. The brief challenges that, and the
 * challenge is correct: if Agent A and Agent B both reach destination X but
 * need ALLOW and DENY respectively, a (daddr, dport) key holds one verdict and
 * cannot express both.
 *
 * Phase 5 established that at cgroup/connect4 the kernel cannot see any L7
 * principal. So the enforcement identity must be something the kernel CAN see
 * and that the control plane can bind to a policy class:
 *
 *     cgroup id   -- one cgroup per policy class
 *     socket mark -- SO_MARK stamped by the gateway before connect()
 *
 * This program keys on (enforcement_identity, daddr, dport) and supports both
 * carriers, so the two can be compared directly.
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define VERDICT_DENY     0
#define VERDICT_ALLOW    1
#define VERDICT_RESTRICT 2

/* key carrier selection: 0 = cgroup id, 1 = socket mark */
#define CARRIER_CGROUP 0
#define CARRIER_MARK   1

struct policy_key {
    __u64 enforcement_id;   /* cgroup id or mark, per carrier config */
    __u32 daddr;
    __u16 dport;
    __u16 pad;
};

struct verdict {
    __u32 action;
    __u32 policy_class;
    __u64 hits;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1048576);
    __type(key, struct policy_key);
    __type(value, struct verdict);
} policy SEC(".maps");

/* Destination-only map, kept alongside so the two keyings can be compared
 * in the same run. */
struct dest_key { __u32 daddr; __u16 dport; __u16 pad; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dest_key);
    __type(value, struct verdict);
} dest_only SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} cfg SEC(".maps");   /* [0] = carrier, [1] = default_action */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 i)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &i);
    if (v) __sync_fetch_and_add(v, 1);
}

static __always_inline __u64 cfg_get(__u32 i, __u64 dflt)
{
    __u64 *v = bpf_map_lookup_elem(&cfg, &i);
    return v ? *v : dflt;
}

SEC("cgroup/connect4")
int enforce(struct bpf_sock_addr *ctx)
{
    if (ctx->protocol != IPPROTO_TCP)
        return 1;

    __u32 daddr = ctx->user_ip4;
    __u16 dport = bpf_ntohs(ctx->user_port);
    __u64 carrier = cfg_get(0, CARRIER_CGROUP);

    __u64 eid;
    if (carrier == CARRIER_MARK) {
        /* The gateway stamps the policy class into the socket mark before
         * connect(). Readable here; not forgeable by an unprivileged
         * workload, since SO_MARK needs CAP_NET_ADMIN. */
        eid = (__u64)ctx->msg_src_ip4;   /* placeholder, see note below */
        eid = 0;
        struct bpf_sock *sk = ctx->sk;
        if (sk)
            eid = (__u64)sk->mark;
    } else {
        eid = bpf_get_current_cgroup_id();
    }

    struct policy_key k = {};
    k.enforcement_id = eid;
    k.daddr = daddr;
    k.dport = dport;

    __u32 action = (__u32)cfg_get(1, VERDICT_DENY);   /* default-deny */
    __u32 pclass = 0;

    struct verdict *v = bpf_map_lookup_elem(&policy, &k);
    if (v) {
        action = v->action;
        pclass = v->policy_class;
        __sync_fetch_and_add(&v->hits, 1);
        bump(2);
    } else {
        bump(3);   /* no matching (identity, destination) rule */
    }

    bump(0);
    if (action == VERDICT_DENY) {
        bump(1);
        return 0;
    }
    return 1;
}

char _license[] SEC("license") = "GPL";
