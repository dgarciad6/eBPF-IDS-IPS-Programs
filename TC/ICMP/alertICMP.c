/**
 * @author David García Diez
 * 
 * eBPF program that alerts about ICMP traffic using Traffic Control (tc).
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/in.h>

#define TC_ACT_OK 0

SEC("classifier")
int alertICMP(struct __sk_buff *skb) {
    struct ethhdr eth;
    struct iphdr ip;

    // Leer la cabecera Ethernet
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
        return TC_ACT_OK;
    }

    // Verificar que sea un paquete IPv4
    if (eth.h_proto != __constant_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    // Leer la cabecera IP
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &ip, sizeof(ip)) < 0) {
        return TC_ACT_OK;
    }

    // Verificar si es un paquete ICMP
    if (ip.protocol == IPPROTO_ICMP) {
        char fmt[] = "[ALERT] ICMP traffic detected.\n";
        bpf_trace_printk(fmt, sizeof(fmt));
    }

    return TC_ACT_OK;
}

// Licencia
char __license[] SEC("license") = "GPL";
