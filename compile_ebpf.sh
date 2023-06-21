bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -D__TARGET_ARCH_x86 -g -target bpf -c main.bpf.c -o main.bpf.o
sudo bpftool gen skeleton main.bpf.o > main.skel.h
gcc -o main main.c -lbpf