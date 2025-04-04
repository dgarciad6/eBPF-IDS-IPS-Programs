/**
 * @author David García Diez
 * 
 * eBPF program that allerts about UDP traffic.
 * 
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/in.h>

// Function to alert about UDP traffic
static __always_inline int alertPacketsUDP(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Verify Ethernet header
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }

    struct ethhdr *eth = data;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Verify IP header
    data += sizeof(struct ethhdr);
    if (data + sizeof(struct iphdr) > data_end) {
        return XDP_PASS;
    }

    // Verify UDP traffic
    struct iphdr *ip = data;
    if (ip->protocol == IPPROTO_UDP) {
        char fmt[] = "[ALERT] UDP traffic detected.\n";
        bpf_trace_printk(fmt, sizeof(fmt));
        return XDP_PASS;
    }

    return XDP_PASS;
}

// XDP program
SEC("xdp")
int alertUDP(struct xdp_md *ctx) {
    return alertPacketsUDP(ctx);
}

// License
char __license[] SEC("license") = "GPL";
