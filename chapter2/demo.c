#include <stdio.h>

#include "bpf/libbpf.h"
#include "bpf/libbpf_legacy.h"
#include "demo.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args){
    return vfprintf(stderr, format, args);
}

int main(int argc, char*argv[])
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    struct demo *skel = demo__open();

    if (demo__load(skel) != 0) {
        fprintf(stderr, "Failed to load BPF skeleton");
        return 1;
    }

    if (demo__attach(skel) != 0) {
        fprintf(stderr, "Failed to attach BPF skeleton");
        return 1;
    }

    for(;;){}
    return 0;

}
