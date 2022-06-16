#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
unsigned long long load_byte(void *skb, unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_hald(void *skb, unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb, unsigned long long off) asm("llvm.bpf.load.word");


#define debug(...) bpf_printk(__VA_ARGS__)

#define ETH_HLEN 14

// thernet protocol
#define ETH_P_8021Q  0X8100         // 802.1Q Vlan Extended Header
#define ETH_P_8021AD 0x88A8         // 801.ad service vlan
#define ETH_P_IP     0x0800
#define ETH_P_IPV6 0x86DD

// ip flags
#define IP_CE       0x8000      /* Flag: "Congestion"       */
#define IP_DF       0x4000      /* Flag: "Don't Fragment"   */
#define IP_MF       0x2000      /* Flag: "More Fragments"   */
#define IP_OFFSET   0x1FFF      /* "Fragment Offset" part   */


#define PROG(F) SEC("socket/"#F) int bpf_func_##F

#define PARSE_VLAN 1
#define PARSE_MPLS 2
#define PARSE_IP 3
#define PARSE_IPV6 4

// 增加尾调用
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 8);
} jmp_table SEC(".maps");


static inline void parse_eth_proto(struct __sk_buff *skb, u32 proto)
{
    switch (proto) {
    case ETH_P_8021Q:
    case ETH_P_8021AD:
        bpf_tail_call(skb, &jmp_table, PARSE_VLAN);
        break;
    case ETH_P_IP:
        debug("debug parse_eth_prot o %x %x\n", proto, ETH_P_IP);
        bpf_tail_call(skb, &jmp_table, PARSE_IP);
        break;
    case ETH_P_IPV6:
        bpf_tail_call(skb, &jmp_table, PARSE_IPV6);
        break;
    }
}

struct flow_key_record{
    __be32 src_addr;
    __be32 dst_addr;
    union {
        __be32 ports;
        __be16 port[2];
    };
    __u8 ip_proto;
};

struct globals {
    struct flow_key_record flow;
};


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value , struct globals);
    __uint(max_entries, 32);
} percpu_map SEC(".maps");


static inline int ip_is_fragment(struct __sk_buff *skb, __u64 off)
{
    return load_hald(skb, off + offsetof(struct iphdr, frag_off)) & (IP_MF|IP_OFFSET);
}

static inline  __u32 ipv6_addr_hash(struct __sk_buff *skb, __u64 off)
{
    __u64 w0 = load_word(skb, off);
    __u64 w1 = load_word(skb, off+4);
    __u64 w2 = load_word(skb, off+8);
    __u64 w3 = load_word(skb, off+12);
    return (__u32)(w0 ^ w1 ^w2 ^ w3);
}


static struct globals *this_cpu_globals(void) 
{
    u32 key = bpf_get_smp_processor_id();
    return bpf_map_lookup_elem(&percpu_map, &key);
}

struct pair {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key_record);
    __type(value, struct pair);
    __uint(max_entries, 1024);
} hash_map SEC(".maps");

static void update_status(struct __sk_buff *skb, struct globals *g)
{
    struct flow_key_record key = g->flow;
    struct pair *value;

    value = bpf_map_lookup_elem(&hash_map, &key);
    if (value) {
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, skb->len);
    }else {
        struct pair val = {1, skb->len};
        bpf_map_update_elem(&hash_map, &key, &val, BPF_ANY);
    }
}

static __always_inline void parse_ip_proto(struct __sk_buff *skb, struct globals *g, __u32 ip_proto)
{
    __u32 nhoff = skb->cb[0];
    int poff;
    switch (ip_proto) {
    case IPPROTO_IPIP:
        parse_eth_proto(skb, ETH_P_IP);
        break;
    case IPPROTO_IPV6:
        parse_eth_proto(skb, ETH_P_IPV6);
        break;
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        g->flow.ports = load_word(skb, nhoff);
    case IPPROTO_ICMP:
        g->flow.ip_proto = ip_proto;
        update_status(skb, g);
        break;
    default:
        break;
    }
}

// parse vlan frams
PROG(PARSE_VLAN)(struct __sk_buff *skb) 
{
    debug("debug vlan");
    __u32 nhoff, proto;
    nhoff = skb->cb[0];
    proto = load_hald(skb, nhoff + offsetof(struct vlan_hdr, h_vlan_encapsulated_proto));
    nhoff += sizeof(struct vlan_hdr);
    skb->cb[0] = nhoff;

    parse_eth_proto(skb, proto);

    return 0;
}

// parse ipv6 frams
PROG(PARSE_IPV6)(struct __sk_buff *skb)
{
    debug("debug ipv6");
    struct globals *g = this_cpu_globals();
    __u32 nhoff, ip_proto;
    if (!g) {
        return 0;
    }
    nhoff = skb->cb[0];
    ip_proto = load_byte(skb, nhoff + offsetof(struct ipv6hdr, nexthdr));
    g->flow.src_addr = ipv6_addr_hash(skb, nhoff + offsetof(struct ipv6hdr, saddr));
    g->flow.dst_addr = ipv6_addr_hash(skb, nhoff + offsetof(struct ipv6hdr, daddr));
    nhoff += sizeof(struct ipv6hdr);
    skb->cb[0] = nhoff;
    // parse -ip proto
    parse_ip_proto(skb, g, ip_proto);
    return 0;
}
// arse ip frams
PROG(PARSE_IP)(struct __sk_buff *skb)
{
    debug("debug parse ip");
    struct globals *g = this_cpu_globals();
    __u32 nhoff, verlen, ip_proto;
    if (!g) {
        return 0;
    }
    nhoff = skb->cb[0];
    if (unlikely(ip_is_fragment(skb, nhoff))) {
        return 0;
    }
    ip_proto = load_byte(skb, nhoff + offsetof(struct iphdr, protocol));
    if (ip_proto != IPPROTO_GRE) {
        g->flow.src_addr = load_word(skb, nhoff+offsetof(struct iphdr, saddr));
        g->flow.dst_addr = load_word(skb, nhoff+offsetof(struct iphdr, daddr));
    }
    verlen = load_byte(skb, nhoff);
    nhoff += (verlen & 0x0F) << 2;
    skb->cb[0] = nhoff;
    parse_ip_proto(skb, g, ip_proto);
    return 0;
}
// parse mpls frame
PROG(PARSE_MPLS)(struct __sk_buff *skb)
{
    return 0;
}



SEC("socket") int handle_socket_filter(struct __sk_buff *skb)
{
    __u32 nhoff = ETH_HLEN;
    __u32 proto = load_hald(skb, 12);
    // sk_buff->cb is This is the control buffer It is free to use for every layer
    // Please put your private variables there.,if we want to keep them across layers you have to do a skb_clone()
    // This is owned by whoever has the skb queued ATM.
    skb->cb[0] = nhoff;

    parse_eth_proto(skb, proto);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
