/**
 * @author David García Diez
 * 
 * eBPF program that discards incoming ICMP packets.
 * The bpf_trace_printk function is used for debugging purposes, 
 * so it must be commented out or removed if better performance is desired.
 * 
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/in.h>

// Function used to block ICMP packets
static __always_inline int blockPacketsICMP(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Verify the Ethernet header
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }

    struct ethhdr *eth = data;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Verify the IP header
    data += sizeof(struct ethhdr);
    if (data + sizeof(struct iphdr) > data_end) {
        return XDP_PASS;
    }
    // Verify if ICMP is used
    struct iphdr *ip = data;
    if (ip->protocol == IPPROTO_ICMP) {
        char fmt[] = "[DROP] ICMP traffic detected.\n";
        bpf_trace_printk(fmt, sizeof(fmt));
        return XDP_DROP;
    }

    char fmt[] = "[INFO] No ICMP traffic detected.\n";
    bpf_trace_printk(fmt, sizeof(fmt));

    return XDP_PASS;
}

// XDP Main Section
SEC("xdp")
int blockICMP(struct xdp_md *ctx) {
    return blockPacketsICMP(ctx);
}

// License
char __license[] SEC("license") = "GPL";
