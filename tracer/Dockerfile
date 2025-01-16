# Use Ubuntu 24.04 (Noble Numbat) as base
FROM ubuntu:noble

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Set Go version - using latest stable version
ENV GO_VERSION=1.22.1

# Install essential packages and dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    cmake \
    pkg-config \
    clang \
    llvm \
    libelf-dev \
    libcap-dev \
    libbfd-dev \
    binutils-dev \
    bison \
    flex \
    linux-headers-generic \
    linux-tools-generic \
    linux-tools-common \
    gdb \
    strace \
    curl \
    wget \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN curl -OL https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz

# Set Go environment variables
ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin

# Install bpftool
RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git \
    && cd bpftool/src \
    && make \
    && make install

# Install libbpf
RUN git clone https://github.com/libbpf/libbpf.git \
    && cd libbpf/src \
    && make \
    && make install \
    && ldconfig

# Generate vmlinux.h
RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > /usr/include/vmlinux.h

# Create necessary directories with appropriate permissions
RUN mkdir -p /sys/kernel/debug \
    && mkdir -p /sys/kernel/btf \
    && mkdir -p /kernel-headers \
    && chmod 755 /kernel-headers

# Create workspace directory
WORKDIR /workspace

# Copy source files
COPY . .

# Build the tracer
RUN go mod download && \
    make

# Add entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Add PID argument
ARG TARGET_PID
ENV TARGET_PID=${TARGET_PID}

ENTRYPOINT ["/entrypoint.sh"]
