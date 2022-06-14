CC=clang
BPFTOOL=/usr/local/bin/bpftool
INCLUDE=-I/home/l0calh0st/lib
CFLAGS=-g -O2 -Wall
LINKERS=/home/l0calh0st/lib/libbpf.so
RM=rm -f

APP=demo

.PHONY: $(APP)
$(APP):
	$(CC) $(CFLAGS) demo.c -l elf $(INCLUDE)  -o $(APP)  /home/l0calh0st/lib/bpf/libbpf.so

.PHONY: vmlinux
vmlinux:
	$(BPFTOOL) btf dump file  /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	$(CC)  $(CFLAGS) $(INCLUDE) -target bpf  -c demo.bpf.c  -o demo.bpf.o


.PHONY: skel
skel: bpf
	$(BPFTOOL) gen skeleton demo.bpf.o  name demo  > demo.skel.h



.PHONY: clean
clean:
	$(RM) *.o vmlinux.h demo
