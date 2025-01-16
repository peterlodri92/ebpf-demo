.PHONY: all clean vmlinux build generate

VMLINUX := vmlinux.h
CLANG ?= clang
CFLAGS := -O2 -g -Wall

all: vmlinux generate build

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
	cp $(VMLINUX) pkg/bpf/

generate: vmlinux
	cd cmd/tracer && CGO_ENABLED=1 go generate

build: generate
	cd cmd/tracer && CGO_ENABLED=1 go build -o ../../tracer

clean:
	rm -f $(VMLINUX)
	rm -f pkg/bpf/$(VMLINUX)
	rm -f tracer
	rm -f cmd/tracer/bpf_*.go
	rm -f *.o