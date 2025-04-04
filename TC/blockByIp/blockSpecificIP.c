/**
 * @author David García Diez
 * 
 * eBPF program that blocks traffic from a specific IP using Traffic Control (tc).
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/in.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2  // Bloquear paquete

// IP bloqueada en formato network-byte order (ejemplo: 192.168.1.100)
#define BLOCKED_IP __constant_htonl(0xC0A80164) // 192.168.1.100

SEC("classifier")
int blockSpecificIP(struct __sk_buff *skb) {
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

    // Verificar si la IP de origen es la bloqueada
    if (ip.saddr == BLOCKED_IP) {
        char fmt[] = "[BLOCKED] Traffic blocked from IP: %d.%d.%d.%d\n";
        bpf_trace_printk(fmt, sizeof(fmt),
                         (ip.saddr >> 24) & 0xFF,
                         (ip.saddr >> 16) & 0xFF,
                         (ip.saddr >> 8) & 0xFF,
                         ip.saddr & 0xFF);
        //return TC_ACT_SHOT;  // Bloquear paquete
    }

    return TC_ACT_OK;
}

// Licencia
char __license[] SEC("license") = "GPL";
