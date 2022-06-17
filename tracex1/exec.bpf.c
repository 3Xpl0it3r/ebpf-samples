#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define	IFNAMSIZ	16


// function prototype 
// static int __netif_receive_skb_core(struct sk_buff **pskb, bool pfmemalloc, struct packet_type **ppt_prev))
// SEC("kprobe/__netif_receive_skb_core.constprop.0")
int bpf_prog1(struct pt_regs *ctx)
{

    // attach to kprobe __netif_receive_skb_core
    // looks for packets on lookpack device and print item
    char devname[IFNAMSIZ];
    struct net_device *dev;
    struct sk_buff *skb;
    int len = 0;
    // 
    //
    // read the first argument
   
    bpf_probe_read_kernel(&skb, sizeof(skb), (void*)PT_REGS_PARM1(ctx));
    bpf_probe_read_kernel(&len, sizeof(len), &skb->len);
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    bpf_probe_read_kernel_str(devname,sizeof(devname), skb->dev->name);
    bpf_printk("skb interface is : %d  isPfmemalloc: %s", len, devname);
    return 0;
}

// static int __netif_receive_skb(struct sk_buff *skb)
SEC("kprobe/__netif_receive_skb")
int bpf_prog2(struct pt_regs *ctx)
{
    // attach to kprobe __netif_receive_skb_core
    // looks for packets on lookpack device and print item
    char devname[IFNAMSIZ];
    struct net_device *dev;
    struct sk_buff *skb = (struct sk_buff*)PT_REGS_PARM1(ctx);
    int len;
    // 
    // read the first argument
    bpf_probe_read_kernel(&len, sizeof(len), &skb->len);
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
   
    bpf_probe_read_kernel(devname, sizeof(devname), dev->name);
    bpf_printk("skb if: %s is : %d  : %p", devname,len, skb);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";


