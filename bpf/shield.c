// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

/*
 * blacklist_map: source IPs to unconditionally drop.
 * Key: IPv4 address (network byte order, __u32)
 * Value: __u8 (non-zero = blocked)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u8);
} blacklist_map SEC(".maps");

/*
 * protected_ports_map: set of destination TCP ports that require an ACL lookup.
 * Key: destination port (network byte order, __u16)
 * Value: __u8 (non-zero = port is protected)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u8);
} protected_ports_map SEC(".maps");

/*
 * port_acl_map: per-port IP allowlist.
 * Key: struct port_ip_key { dst_port (network BO), pad, src_ip (network BO) }
 * Value: __u8 (non-zero = allowed)
 *
 * A source IP absent from this map for a protected port is silently dropped
 * (no ICMP, no TCP RST), making the port invisible to port scanners.
 */
struct port_ip_key {
    __u16 dst_port;
    __u16 pad;
    __u32 src_ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct port_ip_key);
    __type(value, __u8);
} port_acl_map SEC(".maps");

SEC("xdp")
int xdp_shield_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* ── Ethernet ── */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* ── IPv4 ── */
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;

    /* 1. Blacklist — drop traffic from explicitly blocked IPs regardless of port. */
    __u8 *blocked = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (blocked)
        return XDP_DROP;

    /* 2. Per-port ACL — only applies to TCP. */
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *th = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void *)(th + 1) > data_end)
        return XDP_PASS;

    __u16 dst_port = th->dest;

    __u8 *is_protected = bpf_map_lookup_elem(&protected_ports_map, &dst_port);
    if (!is_protected)
        return XDP_PASS;

    /* Port is protected — verify that this source IP is explicitly allowed. */
    struct port_ip_key key = {};
    key.dst_port = dst_port;
    key.pad      = 0;
    key.src_ip   = src_ip;

    __u8 *allowed = bpf_map_lookup_elem(&port_acl_map, &key);
    if (!allowed)
        return XDP_DROP;

    return XDP_PASS;
}
