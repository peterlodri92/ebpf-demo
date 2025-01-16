#!/bin/bash
set -e

# Mount debugfs if not already mounted
if ! mountpoint -q /sys/kernel/debug; then
    mount -t debugfs debugfs /sys/kernel/debug
fi

# Mount tracefs if not already mounted
if ! mountpoint -q /sys/kernel/tracing; then
    mount -t tracefs tracefs /sys/kernel/tracing
fi

# Ensure bpf filesystem is mounted
if ! mountpoint -q /sys/fs/bpf; then
    mount -t bpf bpf /sys/fs/bpf
fi

# Set kernel.perf_event_paranoid to -1 to allow perf monitoring
sysctl -w kernel.perf_event_paranoid=-1

# Set kernel.kptr_restrict to 0 to allow reading kernel symbols
sysctl -w kernel.kptr_restrict=0

# Generate vmlinux.h from host kernel
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
cp vmlinux.h pkg/bpf/

# Build the tracer with host's kernel headers
make clean
make

# Update dynamic linker
ldconfig

# Check if TARGET_PID is set
if [ -z "${TARGET_PID}" ]; then
    echo "Error: TARGET_PID environment variable is not set"
    exit 1
fi

# Verify the PID exists in the host namespace
if ! kill -0 "${TARGET_PID}" 2>/dev/null; then
    echo "Error: Process ${TARGET_PID} not found in host namespace"
    exit 1
fi

echo "Starting tracer for PID ${TARGET_PID}..."
exec ./tracer -pid "${TARGET_PID}"
