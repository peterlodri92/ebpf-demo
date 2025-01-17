#!/bin/bash
set -e

echo "Mounting filesystems..."

# Mount debugfs
if mountpoint -q /sys/kernel/debug; then
    echo "debugfs is already mounted"
else
    echo "Mounting debugfs..."
    mount -t debugfs none /sys/kernel/debug
    if [ $? -eq 0 ]; then
        echo "debugfs mounted successfully"
    else
        echo "Failed to mount debugfs"
        exit 1
    fi
fi

# Mount tracefs
if mountpoint -q /sys/kernel/tracing; then
    echo "tracefs is already mounted"
else
    echo "Mounting tracefs..."
    mount -t tracefs none /sys/kernel/tracing
    if [ $? -eq 0 ]; then
        echo "tracefs mounted successfully"
    else
        echo "Failed to mount tracefs"
        exit 1
    fi
fi

# Mount bpf filesystem
if mountpoint -q /sys/fs/bpf; then
    echo "bpf filesystem is already mounted"
else
    echo "Mounting bpf filesystem..."
    mount -t bpf none /sys/fs/bpf
    if [ $? -eq 0 ]; then
        echo "bpf filesystem mounted successfully"
    else
        echo "Failed to mount bpf filesystem"
        exit 1
    fi
fi

# Verify mounts and permissions
echo "Verifying mounts and permissions..."
echo "debugfs mount:"
mount | grep debugfs
ls -la /sys/kernel/debug
echo
echo "tracefs mount:"
mount | grep tracefs
ls -la /sys/kernel/tracing
echo
echo "bpf mount:"
mount | grep bpf
ls -la /sys/fs/bpf
echo
echo "Checking tracing directory:"
ls -la /sys/kernel/tracing/events/sched/

# Set kernel.perf_event_paranoid to -1 to allow perf monitoring
sysctl -w kernel.perf_event_paranoid=-1

# Set kernel.kptr_restrict to 0 to allow reading kernel symbols
sysctl -w kernel.kptr_restrict=0

# Generate vmlinux.h from host kernel
echo "Generating vmlinux.h..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h || \
  { echo "bpftool failed"; exit 1; }
cp vmlinux.h pkg/bpf/

# Build the tracer with host's kernel headers
make clean
echo "Running make..."
make || { echo "make failed"; exit 1; }

# Update dynamic linker
ldconfig

echo "About to run ./tracer..."
./tracer || { echo "./tracer exited with error"; exit 1; }

echo "If we got here, tracer ended by itself"
