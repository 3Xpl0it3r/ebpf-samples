#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <bpf/bpf.h>
#include "bpf/libbpf.h"
#include "bpf/libbpf_legacy.h"
#include "skprog.skel.h"


struct pair{
    long packets;
    long bytes;
};


static volatile bool exiting = false;

static inline void handle_signal()
{
    exiting = true;
}

static inline int open_raw_sock(char *ifname)
{
    int sock = 0;
    sock = socket(AF_PACKET, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, htons(ETH_P_ALL));
    if (sock < 0) {
        return -1;
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex(ifname);
    if (bind(sock, (const struct sockaddr*)&sll, sizeof(sll))) {
        return -1;
    }

    return sock;
}

int main(int argc, char *argv[])
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    int sock, map_fd, prog_fd;

    sock = open_raw_sock("enp0s3");
    // open bpf program
    struct skprogskel *skel = skprogskel__open();
    // load bpf programm
    skprogskel__load(skel);

    prog_fd = bpf_program__fd(skel->progs.handle_bpf_socket_filter);
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
        printf("attatch socker to bpf failed");
        goto cleanup;
    }

    map_fd = bpf_map__fd(skel->maps.hash_map);

    while (exiting == false) {
		int key = 0, next_key;
		struct pair value;

		while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
			bpf_map_lookup_elem(map_fd, &next_key, &value);
			printf("ip %s bytes %ld packets %ld\n",
			       inet_ntoa((struct in_addr){htonl(next_key)}),
			       value.bytes, value.packets);
			key = next_key;
		}
		sleep(1);
    }
cleanup:
    close(sock);
    skprogskel__destroy(skel);

    return 0;
}
