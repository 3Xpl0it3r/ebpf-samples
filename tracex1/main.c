
#include <bpf/bpf.h>
#include <stdbool.h>
#include "bpf/libbpf_legacy.h"
#include "exec.skel.h"

#include <unistd.h>


int main(int argc, char *argv[])
{

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    struct execskel *skel = execskel__open();
    execskel__load(skel);
    execskel__attach(skel);

    while (true) {
        sleep(1);
    }

    return 0;
}
