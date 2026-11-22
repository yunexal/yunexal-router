#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#else
#define bpf_htons(x) (x)
#define bpf_ntohs(x) (x)
#endif

static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*const bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static __u64 (*const bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;

enum {
    STAT_PASSED = 0,
    STAT_DROPPED_BLOCKED = 1,
    STAT_DROPPED_SYN = 2,
    STAT_DROPPED_UDP = 3,
};

enum {
    CFG_MAX_SYN_PPS = 0,
    CFG_MAX_UDP_PPS = 1,
    CFG_WHITELIST_MODE = 2,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} trusted_edges SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} protected_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u64);
} blocked_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} syn_rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} udp_rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

static __always_inline void inc_stat(__u32 idx) {
    __u64 *cnt = bpf_map_lookup_elem(&stats_map, &idx);
    if (cnt) {
        (*cnt)++;
    }
}

static __always_inline __u32 get_cfg(__u32 idx, __u32 fallback) {
    __u32 *val = bpf_map_lookup_elem(&config_map, &idx);
    if (val && *val > 0) {
        return *val;
    }
    return fallback;
}

static __always_inline int check_rate_limit(void *map, __u32 src_ip, __u64 now_ns, __u32 limit) {
    __u32 win = (__u32)(now_ns >> 30); /* ~1.07s tumbling window */
    __u64 *entry = bpf_map_lookup_elem(map, &src_ip);
    if (!entry) {
        __u64 init = ((__u64)win << 32) | 1ULL;
        bpf_map_update_elem(map, &src_ip, &init, BPF_ANY);
        return 1;
    }
    __u64 cur = *entry;
    __u32 prev_win = (__u32)(cur >> 32);
    __u32 count = (__u32)(cur & 0xFFFFFFFFULL);
    if (prev_win != win) {
        __u64 reset = ((__u64)win << 32) | 1ULL;
        bpf_map_update_elem(map, &src_ip, &reset, BPF_ANY);
        return 1;
    }
    if (count >= limit) {
        return 0;
    }
    __u64 next = ((__u64)win << 32) | (__u64)(count + 1);
    bpf_map_update_elem(map, &src_ip, &next, BPF_ANY);
    return 1;
}

SEC("xdp")
int xdp_shield(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 ihl = (__u32)iph->ihl * 4;
    if (ihl < sizeof(*iph) || ihl > 60) {
        return XDP_PASS;
    }
    if ((void *)iph + ihl > data_end) {
        return XDP_PASS;
    }

    __u8 proto = iph->protocol;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
        return XDP_PASS;
    }

    __u16 dst_port = 0;
    __u8 is_tcp_syn = 0;
    __u16 udp_len = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + ihl;
        if ((void *)(tcph + 1) > data_end) {
            return XDP_PASS;
        }
        dst_port = bpf_ntohs(tcph->dest);
        if (tcph->syn && !tcph->ack) {
            is_tcp_syn = 1;
        }
    } else {
        struct udphdr *udph = (void *)iph + ihl;
        if ((void *)(udph + 1) > data_end) {
            return XDP_PASS;
        }
        dst_port = bpf_ntohs(udph->dest);
        udp_len = bpf_ntohs(udph->len);
    }

    __u8 *is_protected = bpf_map_lookup_elem(&protected_ports, &dst_port);
    if (!is_protected) {
        return XDP_PASS;
    }

    __u32 src_ip = iph->saddr;
    __u32 wl_mode = get_cfg(CFG_WHITELIST_MODE, 0);
    if (wl_mode == 1) {
        __u8 *trusted = bpf_map_lookup_elem(&trusted_edges, &src_ip);
        if (!trusted) {
            inc_stat(STAT_DROPPED_BLOCKED);
            return XDP_DROP;
        }
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    __u64 now_ns = bpf_ktime_get_ns();

    __u64 *blocked_until = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (blocked_until && now_ns < *blocked_until) {
        inc_stat(STAT_DROPPED_BLOCKED);
        return XDP_DROP;
    }

    if (proto == IPPROTO_TCP && is_tcp_syn) {
        __u32 max_syn = get_cfg(CFG_MAX_SYN_PPS, 60);
        if (!check_rate_limit(&syn_rate_map, src_ip, now_ns, max_syn)) {
            inc_stat(STAT_DROPPED_SYN);
            return XDP_DROP;
        }
    } else if (proto == IPPROTO_UDP) {
        if (udp_len <= sizeof(struct udphdr)) {
            inc_stat(STAT_DROPPED_UDP);
            return XDP_DROP;
        }
        __u32 max_udp = get_cfg(CFG_MAX_UDP_PPS, 800);
        if (!check_rate_limit(&udp_rate_map, src_ip, now_ns, max_udp)) {
            inc_stat(STAT_DROPPED_UDP);
            return XDP_DROP;
        }
    }

    inc_stat(STAT_PASSED);
    return XDP_PASS;
}

char _license[] SEC("license") = "Dual MIT/GPL";
