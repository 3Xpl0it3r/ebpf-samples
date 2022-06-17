TARGET=exec
INCLUDE=-I/home/l0calh0st/lib
LIBRARY=/home/l0calh0st/lib/bpf/libbpf.so
CC=clang
CFLAGS+=-g -O3
SRC:=$(wildcard *.bpf.c)

BPFTOOL:=/usr/local/bin/bpftool

.PHONY: $(TARGET)
$(TARGET): skel
	$(CC) main.c $(INCLUDE) $(LIBRARY) -lelf -o $@

.PHONY: vmlinux
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf:vmlinux $(SRC:.c=.o)

.PHONY: skel
skel: bpf

%.bpf.o: %.bpf.c
	$(CC) $(CFLAGS) $(INCLUDE) -target bpf  -D__TARGET_ARCH_x86_64 -c $^ -o $@
	$(BPFTOOL) gen skeleton $@ name $(patsubst %.bpf.o,%skel, $@) > $(patsubst %.bpf.o,%.skel.h, $@)

.PHONY: clean
clean:
	$(RM) *.o *.skel.h vmlinux.h $(TARGET)
