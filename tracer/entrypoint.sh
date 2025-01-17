#!/bin/bash
set -e

echo "Mounting filesystems..."

# Create mount points if they don't exist
mkdir -p /sys/kernel/debug
mkdir -p /sys/kernel/tracing

# Mount debugfs
echo "Mounting debugfs..."
mount -t debugfs none /sys/kernel/debug || true

# Mount tracefs
echo "Mounting tracefs..."
mount -t tracefs none /sys/kernel/tracing || true

# Verify mounts
if ! mountpoint -q /sys/kernel/debug; then
    echo "Failed to mount debugfs"
    exit 1
fi

if ! mountpoint -q /sys/kernel/tracing; then
    echo "Failed to mount tracefs"
    exit 1
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

# Wait for FastAPI to start and get its PID
echo "Waiting for FastAPI to start..."
sleep 5
FASTAPI_PID=$(ps aux | grep "[u]vicorn" | awk '{print $2}')
if [ -n "$FASTAPI_PID" ]; then
  echo "Found FastAPI PID: $FASTAPI_PID"
  /tracer --pid=$FASTAPI_PID
else
  echo "Could not find FastAPI process"
  exit 1
fi


echo "If we got here, tracer ended by itself"
