#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "exec.h"


// copy from uapi/linux/if_ether.h
#define ETH_HLEN	14		/* Total octets in header.	 */
#define PACKET_OUTGOING		4		/* Outgoing of any type */



#ifndef offsetof
#define offsetof(TYPE, MEMBER)	((unsigned long)&((TYPE *)0)->MEMBER)
#endif


unsigned long long load_byte(void *skb, unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb, unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb, unsigned long long off) asm("llvm.bpf.load.word");




struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, long);
	__uint(max_entries, 256);
} my_map SEC(".maps");

SEC("socket1")
int socket_handler(struct __sk_buff *skb)
{
    int index = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
    long *value;
    if (skb->pkt_type != PACKET_OUTGOING) return 0;
    value = bpf_map_lookup_elem(&my_map, &index);

    /*
     *
     * The lookup (from kernel side) bpf_map_lookup_elem() returns a pointer into the array element. 
     * To avoid data races with userspace reading the value, the API-user must use primitives like __sync_fetch_and_add() when updating the value in-place
     */
    if (value)  __sync_fetch_and_add(value, skb->len);

    return 0;
}


char LICENSE[] SEC("license") = "GPL";
