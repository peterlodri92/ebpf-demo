#ifndef __TRACER_H
#define __TRACER_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Basic type definitions if not already defined
#ifndef __u8
typedef unsigned char __u8;
#endif
#ifndef __u16
typedef unsigned short __u16;
#endif
#ifndef __u32
typedef unsigned int __u32;
#endif
#ifndef __u64
typedef unsigned long long __u64;
#endif

// Event structure to pass data to userspace
struct event
{
    __u32 pid;
    __u32 ppid;
    __u64 timestamp;
    __u64 syscall_id;
    char comm[16];
};

// BPF map definitions
#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct                                                          \
    {                                                               \
        __uint(type, _type);                                        \
        __uint(max_entries, _max_entries);                          \
        __type(key, _key_type);                                     \
        __type(value, _value_type);                                 \
    } _name SEC(".maps")

#endif /* __TRACER_H */
