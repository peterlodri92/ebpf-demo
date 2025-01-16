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
    libbpf-dev \
    gdb \
    strace \
    curl \
    wget \
    vim \
    linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN curl -OL https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz

# Set Go environment variables
ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin

# Set up kernel headers and BPF includes
RUN mkdir -p /usr/include/linux && \
    ln -sf /usr/include/asm-generic /usr/include/asm && \
    ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm-x86 && \
    ln -sf /usr/include/x86_64-linux-gnu/sys /usr/include/sys && \
    ln -sf /usr/include/x86_64-linux-gnu/bits /usr/include/bits && \
    ln -sf /usr/lib/x86_64-linux-gnu/libbpf.so /usr/lib/libbpf.so && \
    ln -sf /usr/include/x86_64-linux-gnu/bpf /usr/include/bpf && \
    ln -sf /usr/include/x86_64-linux-gnu/linux/bpf.h /usr/include/linux/bpf.h && \
    ln -sf /usr/include/x86_64-linux-gnu/linux/bpf_common.h /usr/include/linux/bpf_common.h && \
    ln -sf /usr/include/x86_64-linux-gnu/linux/types.h /usr/include/linux/types.h

# Install bpftool
RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git \
    && cd bpftool/src \
    && make \
    && make install

# Install libbpf and set up headers
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
