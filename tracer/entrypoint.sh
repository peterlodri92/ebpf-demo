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

# Set kernel parameters
echo "Setting kernel parameters..."
sysctl -w kernel.perf_event_paranoid=-1 || true
sysctl -w kernel.kptr_restrict=0 || true

if [ -n "$TRACE_PID" ]; then
  echo "Starting tracer with PID $TRACE_PID..."
  exec /tracer --pid=$TRACE_PID
else
  echo "Starting tracer without specific PID filter..."
  exec /tracer
fi


echo "If we got here, tracer ended by itself"
