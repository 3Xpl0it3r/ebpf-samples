#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <assert.h>
#include <signal.h>

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "bpf/libbpf_legacy.h"
#include "exec.skel.h"
#include "exec.h"


static volatile bool exiting = false;

static inline int open_raw_socket(const char *filename)
{
    struct sockaddr_ll sll;
    int sock;

    sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (sock < 0) {
		printf("cannot create raw socket\n");
		return -1;
	}

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(filename);
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll))) {
        close(sock);
        return 0;
    }

    return sock;
}



static void sig_handler(int sig)
{
    exiting = true;
}

int main(void)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    int sock = open_raw_socket("enp0s3");


    // open phase
    struct exec *skel = exec__open();
    // load phase
    exec__load(skel);

    // attach SOCKET_FILTER type bpf code to a special interface
    int prog_fd = bpf_program__fd(skel->progs.socket_handler);
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) != 0) {
        fprintf(stderr, "Set socket opts failed");
        return -1;
    }

    int map_fd = bpf_map__fd(skel->maps.my_map);

    while (!exiting) {
        long long tcp_cnt, udp_cnt, icmp_cnt;
		int key;
        key = IPPROTO_TCP;
		assert(bpf_map_lookup_elem(map_fd, &key, &tcp_cnt) == 0);

		key = IPPROTO_UDP;
		assert(bpf_map_lookup_elem(map_fd, &key, &udp_cnt) == 0);

		key = IPPROTO_ICMP;
		assert(bpf_map_lookup_elem(map_fd, &key, &icmp_cnt) == 0);

		printf("TCP %lld UDP %lld ICMP %lld bytes\n", tcp_cnt, udp_cnt, icmp_cnt);
		sleep(1);
    }


    exec__detach(skel);
    exec__destroy(skel);

