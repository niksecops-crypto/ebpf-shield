// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") blacklist_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};

struct bpf_map_def SEC("maps") settings_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

SEC("xdp")
int xdp_shield_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
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
            struct tcphdr *th = (void *)(iph + 1);
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
