// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} blacklist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} settings_map SEC(".maps");

SEC("xdp")
int xdp_shield_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // Check blacklist
    __u32 src_ip = iph->saddr;
    __u32 *val = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (val) {
        return XDP_DROP;
    }

    // Example of obfuscation: Hide a port (e.g. 8080) from all except a trusted IP
    // Trusted IP is stored in settings_map at index 0
    __u32 index = 0;
    __u32 *trusted_ip = bpf_map_lookup_elem(&settings_map, &index);
    if (trusted_ip && *trusted_ip != 0) {
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *th = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if ((void *)(th + 1) <= data_end) {
                // If destination is our "secret" proxy port (8080)
                if (th->dest == bpf_htons(8080)) {
                    if (src_ip != *trusted_ip) {
                        // Drop if not from trusted IP - effectively hiding the port
                        return XDP_DROP;
                    }
                }
            }
        }
    }

    return XDP_PASS;
}
