APP=exec
INCLUDE=-I/home/l0calh0st/lib
LIBRARY=/home/l0calh0st/lib/bpf/libbpf.so
RM=rm -f

.PHONY: $(APP)
$(APP): skel
	clang exec.c $(INCLUDE) $(LIBRARY) -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -g -O3 $(INCLUDE) -target bpf -D__TARGET_ARCH_x86_64 -c exec.bpf.c -o exec.bpf.o

.PHONY: skel
skel: bpf
	bpftool gen skeleton exec.bpf.o name exec > exec.skel.h

.PHONY: run
run: $(APP)
	sudo ./$(APP)

.PHONY: clean
clean:
	$(RM) *.o *.skel.h vmlinux.h $(APP)
