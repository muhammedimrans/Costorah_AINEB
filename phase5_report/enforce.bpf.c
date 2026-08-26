// Phase 5 RQ1: a real eBPF enforcement datapath.
//
// Models what Cilium does and what a "verdict channel" from an L7 verifier
// would have to do: userspace writes a verdict into a map, the datapath
// enforces it at connect() time, before any bytes leave the host.
//
// The point of the experiment is what the datapath can SEE. At the
// cgroup/connect4 hook the kernel offers destination address, destination
// port, protocol, and the socket cookie. There is no L7 principal anywhere
// in this context, and there cannot be: connect() happens once, before the
// first request is written.

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define VERDICT_ALLOW    1
#define VERDICT_DENY     0
#define VERDICT_RESTRICT 2

struct flow_key {
    __u32 daddr;
    __u16 dport;
    __u16 pad;
};

struct verdict {
    __u32 action;       // ALLOW / DENY / RESTRICT
    __u32 principal_id; // what the L7 verifier claims owns this flow
    __u64 expires_ns;
    __u64 hits;
};

// The verdict channel: written by userspace (standing in for an L7 verifier),
// read by the datapath.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct verdict);
} verdicts SEC(".maps");

// What the datapath actually observed, for the attribution analysis.
struct observation {
    __u64 socket_cookie;
    __u32 daddr;
    __u16 dport;
    __u16 action_taken;
    __u64 ts_ns;
    __u32 pid;
    __u32 uid;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

// Counters so the test can assert without parsing the ring buffer.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

SEC("cgroup/connect4")
int enforce_connect4(struct bpf_sock_addr *ctx)
{
    if (ctx->protocol != IPPROTO_TCP)
        return 1;

    struct flow_key k = {};
    k.daddr = ctx->user_ip4;
    k.dport = bpf_ntohs(ctx->user_port);

    __u64 cookie = bpf_get_socket_cookie(ctx);
    __u64 id = bpf_get_current_pid_tgid();
    __u64 uidgid = bpf_get_current_uid_gid();

    __u32 action = VERDICT_ALLOW;
    __u32 principal = 0;

    struct verdict *v = bpf_map_lookup_elem(&verdicts, &k);
    if (v) {
        if (v->expires_ns == 0 || bpf_ktime_get_ns() < v->expires_ns) {
            action = v->action;
            principal = v->principal_id;
            __sync_fetch_and_add(&v->hits, 1);
        } else {
            bump(3); // expired verdict
        }
    } else {
        bump(4); // no verdict present -> default
    }

    struct observation *o = bpf_ringbuf_reserve(&events, sizeof(*o), 0);
    if (o) {
        o->socket_cookie = cookie;
        o->daddr = k.daddr;
        o->dport = k.dport;
        o->action_taken = action;
        o->ts_ns = bpf_ktime_get_ns();
        o->pid = id >> 32;
        o->uid = (__u32)uidgid;
        bpf_ringbuf_submit(o, 0);
    }

    bump(0); // connect attempts seen
    if (action == VERDICT_DENY) {
        bump(1); // blocked
        return 0; // reject the connect()
    }
    bump(2); // allowed
    return 1;
}

char _license[] SEC("license") = "GPL";
