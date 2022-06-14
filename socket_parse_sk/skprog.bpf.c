#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


unsigned long long load_byte(void *skb, long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb, long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb, long long off) asm("llvm.bpf.load.word");


#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)


// type ethernet type define
#define ETH_LEN 14  // 以太网头部总共字节长度14个字节(6个字节dMac, 6个字节sMac, 2个字节type)  (开头的8个字节比特序列不用软件考虑)
                    //

// Ethernet protocol
#define ETH_P_8021Q  0X8100         // 802.1Q Vlan Extended Header
#define ETH_P_8021AD 0x88A8         // 801.ad service vlan
                                    //
#define ETH_P_IP     0x0800 
#define ETH_P_IPV6 0x86DD


// ip flags
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

 
struct flow_key_record{
    // source ip address
    __be32 src_addr;
    // destionation ip address
    __be32 dst_addr;
    // ports
    union {
        __be32 ports;
        __be16 port16[2];
    };
    __u16 thoff;
    // proto
    __u8 ip_proto;
};


static inline int proto_ports_offset(__u64 proto)
{
    switch (proto) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
    case IPPROTO_DCCP:
    case IPPROTO_ESP:
    case IPPROTO_SCTP:
    case IPPROTO_UDPLITE:
        return 0;
    case IPPROTO_AH: return 4;
    default: return 0;
    }
}

static inline int ip_is_fragment(struct __sk_buff *skb, __u64 nhoff)
{
    // 三位标识Flags 从左到右分别是MF, DF ，未用。
    // 因此只需要读取2个字节，和 MF DF 对比，只要不为0，那么这两个一定会有个被设置1了，那么它就是ip帧
    return load_half(skb, offsetof(struct iphdr, frag_off)) & (IP_MF| IP_OFFSET);
}

static inline __u64 parse_ip(struct __sk_buff *skb, __u64 nhoff, __u64 *ip_proto, struct flow_key_record *flow)
{
    __u64 verlen;
    if (unlikely(ip_is_fragment(skb, nhoff)))  *ip_proto = 0;
    else *ip_proto = load_byte(skb, nhoff + offsetof(struct iphdr, protocol));
    // ip_proto 标识上层使用的协议
    /*
     * 0保留 1 ICMP 2IGMP 3GGP， 4 IPINIP 6TCP 8EGP 17UDP
     */

    if (*ip_proto != IPPROTO_GRE) {
        flow->src_addr = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
        flow->dst_addr = load_word(skb, nhoff + offsetof(struct iphdr, daddr));
    }
    // verlen contains  version(4 bit) ihl(4 bit)
    verlen = load_byte(skb, nhoff + 0);
    if (likely(verlen == 0x45))  nhoff += 20;
    // left shif got the ihl
    else nhoff += (verlen & 0xF) << 2;

    return nhoff;
}

static inline __u32 ipv6_addr_hash(struct __sk_buff *skb, __u64 off)
{
    __u64 w0 = load_word(skb, off + 0);
    __u64 w1 = load_word(skb, off + 4);
    __u64 w2 = load_word(skb, off + 8);
    __u64 w3 = load_word(skb, off+ 12);
    return (__u32)(w0 ^ w1 ^ w2 ^ w3);
}

static inline __u64 parse_ipv6(struct __sk_buff *skb, __u64 nhoff, __u64 *ip_proto, struct flow_key_record *record)
{
    *ip_proto = load_byte(skb, offsetof(struct ipv6hdr, nexthdr));
    record->src_addr = ipv6_addr_hash(skb, offsetof(struct ipv6hdr, saddr));
    record->dst_addr = ipv6_addr_hash(skb, offsetof(struct ipv6hdr, daddr));
    nhoff += sizeof(struct ipv6hdr);
    return 0;

}

// 将_sk_buff解码到flow_key_record结构里面
static inline bool flow_dissector(struct __sk_buff *skb,  struct flow_key_record *record)
{
    __u64 nhoff = ETH_LEN;
    __u64 ip_proto ;
    __u64 proto = load_half(skb, 12);
    int poff;
    if (proto == ETH_P_8021AD) {
        proto = load_half(skb, nhoff + offsetof(struct vlan_hdr, h_vlan_encapsulated_proto));
        nhoff += sizeof(struct vlan_hdr);
    }
    if (proto == ETH_P_8021Q) {
        proto = load_half(skb, nhoff + offsetof(struct vlan_hdr, h_vlan_encapsulated_proto));
        nhoff += sizeof(struct vlan_hdr);
    }
    // parse ip layer
    if (likely(proto == ETH_P_IP))  nhoff = parse_ip(skb, nhoff, &ip_proto, record); 
    else if (likely(proto == ETH_P_IPV6)) nhoff = parse_ipv6(skb, nhoff, &ip_proto, record);
    else return true;
    // ipproto 
    //

    switch (ip_proto) {
    case IPPROTO_IPIP:
        nhoff += parse_ip(skb, nhoff, &ip_proto, record);
        break;
    case IPPROTO_IPV6:
        nhoff += parse_ipv6(skb, nhoff, &ip_proto, record);
        break;
    default: break;
    }

    record->ip_proto = ip_proto;
    poff = proto_ports_offset(ip_proto);
    if (poff > 0) {
        nhoff += poff;
        record->ports = load_word(skb, nhoff);
    }
    record->thoff = (__u64) nhoff;

    return true;
}

struct pair{
    long packets;
    long bytes;
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __be32);
    __type(value, struct pair);
} hash_map SEC(".maps");

SEC("socket")
int handle_bpf_socket_filter(struct __sk_buff *skb)
{
    struct flow_key_record flow = {};
    struct pair *value;
    u32 key;
    if (!flow_dissector(skb, &flow)) {
        return 0;
    }
    key = flow.dst_addr;
    value = bpf_map_lookup_elem(&hash_map, &key);
    
    if (value) {
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes , skb->len);
    }  else {
        struct pair val1 = {1, skb->len};
        bpf_map_update_elem(&hash_map, &key, &val1, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
