#include <bits/types.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>

#include <bpf/bpf.h>
#include "bpf/libbpf.h"
#include "bpf/libbpf_legacy.h"
#include "skprog.skel.h"

#define BPF_TAIL_CALL_REGISTER(M,K,V) {int index=K; int fd = V; bpf_map_update_elem(M, &index,  &fd, 0);}

enum {
    PARSE_VLAN=1,
    PARSE_MPLS=2,
    PARSE_IP=3,
    PARSE_IPV6=4
};

struct flow_key_record {
    __be32 src;
    __be32 dst;
    union{
        __be32 ports;
        __be16 port16[2];
    };
    __u32 ip_proto;
};

struct pair {
    __u64 packets;
    __u64 bytes;
};


static volatile bool exiting = false;
static void handle_signal()
{
    exiting = true;
}


static inline int open_raw_socket(char *if_name)
{
    int sock;
    sock = socket(AF_PACKET, SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC, htons(ETH_P_ALL));
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(if_name);
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll))) {
        return -1;
    }
    return sock;
}


int main(int argc, char *argv[])
{
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    int i, sock, key ,fd , main_prog_fd, jmp_table_fd, hash_map_fd;
    struct bpf_program *prog;
    
    struct skprogskel *skel = skprogskel__open();
    skprogskel__load(skel);

    main_prog_fd = bpf_program__fd(skel->progs.handle_socket_filter);
    jmp_table_fd = bpf_map__fd(skel->maps.jmp_table);
    hash_map_fd = bpf_map__fd(skel->maps.hash_map);

    if (jmp_table_fd < 0 || hash_map_fd < 0) {
        printf("cannot find jmp table or hash map");
        goto cleanup;
    }
    // register bpf prog into prog_map for bpf tail call

    BPF_TAIL_CALL_REGISTER(jmp_table_fd, PARSE_IP, bpf_program__fd(skel->progs.bpf_func_PARSE_IP));
    BPF_TAIL_CALL_REGISTER(jmp_table_fd, PARSE_IPV6, bpf_program__fd(skel->progs.bpf_func_PARSE_IPV6));
    BPF_TAIL_CALL_REGISTER(jmp_table_fd, PARSE_VLAN, bpf_program__fd(skel->progs.bpf_func_PARSE_VLAN));
    BPF_TAIL_CALL_REGISTER(jmp_table_fd, PARSE_MPLS, bpf_program__fd(skel->progs.bpf_func_PARSE_MPLS));

    // for bpf call

    sock = open_raw_socket("enp0s3");
    int err = setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &main_prog_fd, sizeof(main_prog_fd));
    if (err !=0) {
        goto cleanup;
    }

    printf("IP    src.port  ->  dst.port          bytes       packets");
    while (exiting == false) {
        struct flow_key_record key = {}, next_key;
        struct pair value;
        sleep(1);
        while (bpf_map_get_next_key(hash_map_fd, &key, &next_key) == 0) {
            bpf_map_lookup_elem(hash_map_fd, &next_key, &value);
            printf("%s.%05d -> %s.%05d   %12lld   %12lld\n", 
                    inet_ntoa((struct in_addr){htonl(next_key.src)}),
                    next_key.port16[0],
                    inet_ntoa((struct in_addr){htonl(next_key.dst)}),
                    next_key.port16[1],
                    value.bytes, value.packets);
            key = next_key;
        }
    }

cleanup:
    skprogskel__destroy(skel);
    return 0;
}
