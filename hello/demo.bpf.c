#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int handler_execve(void *ctx)
{
    char msg[] = "Hello world";
    bpf_printk(msg);
    return 0;
}

char _license[] SEC("license") = "GPL";
