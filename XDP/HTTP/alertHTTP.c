/**
 * @author David García Diez
 * 
 * eBPF program that allerts about HTTP traffic.
 * 
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/in.h>

// Function to alert about HTTP traffic
static __always_inline int alertPacketsHTTP(struct xdp_md *ctx) {
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

    // Verify TCP traffic
    data += sizeof(struct iphdr);
    if(data + sizeof(struct tcphdr) > data_end) {
	return XDP_PASS;
    }

    struct tcphdr *tcp = data;

    if (tcp->dest == __constant_htons(80)) {
        char fmt[] = "[ALERT] TCP traffic detected on port 80 (HTTP).\n";
        bpf_trace_printk(fmt, sizeof(fmt));
    }

    return XDP_PASS;
}

// XDP program
SEC("xdp")
int alertHTTP(struct xdp_md *ctx) {
    return alertPacketsHTTP(ctx);
}

// License
char __license[] SEC("license") = "GPL";
