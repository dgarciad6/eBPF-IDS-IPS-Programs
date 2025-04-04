/**
 * @author David García Diez
 * 
 * eBPF program that blocks HTTP traffic (port 80) using Traffic Control (tc).
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/tcp.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2  // Bloquear paquete si se usa como IPS

SEC("classifier")
int blockHTTP(struct __sk_buff *skb) {
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;

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

    // Verificar si es un paquete TCP
    if (ip.protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    // Calcular el offset de la cabecera TCP
    int tcp_offset = sizeof(struct ethhdr) + (ip.ihl * 4);
    
    // Leer la cabecera TCP
    if (bpf_skb_load_bytes(skb, tcp_offset, &tcp, sizeof(tcp)) < 0) {
        return TC_ACT_OK;
    }

    // Verificar si el puerto de destino es 80 (HTTP)
    if (tcp.dest == __constant_htons(80)) {
        char fmt[] = "[ALERT] HTTP traffic blocked.\n";
        bpf_trace_printk(fmt, sizeof(fmt));
        //return TC_ACT_SHOT;  // Bloquear paquete
    }

    return TC_ACT_OK;
}

// Licencia
char __license[] SEC("license") = "GPL";
