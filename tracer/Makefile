ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
VMLINUX := vmlinux.h
BPFTOOL ?= $(shell which bpftool)
CLANG ?= clang
CFLAGS := -g -O2 -Wall
INCLUDES := -I$(shell pwd) \
           -I/usr/include/bpf \
           -I/usr/include \
           -I/usr/src/linux-headers-$(shell uname -r) \
           -I/usr/src/linux-headers-$(shell uname -r)/include \
           -I/usr/src/linux-headers-$(shell uname -r)/arch/x86/include \
           -I/usr/src/linux-headers-$(shell uname -r)/arch/x86/include/generated

.PHONY: all clean vmlinux build

all: vmlinux build

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

build: $(VMLINUX)
	CGO_ENABLED=1 go generate
	CGO_ENABLED=1 go build -o tracer

clean:
	rm -f $(VMLINUX)
	rm -f tracer
	rm -f bpf_*.go
	rm -f *.o
