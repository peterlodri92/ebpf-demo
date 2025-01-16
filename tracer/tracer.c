// tracer.c
#include "vmlinux.h"

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

// Basic type definitions
typedef unsigned int pid_t;

// Tracepoint event structures
struct trace_event_raw_sched_process_exec
{
    __u64 pad; // Placeholder to ensure proper alignment
};

struct trace_event_raw_sched_process_template
{
    __u64 pad; // Placeholder to ensure proper alignment
};

// Minimal task_struct definition with only the fields we need
struct task_struct
{
    struct task_struct *real_parent;
    pid_t tgid;
};

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(type, val) __attribute__((btf_decl_tag("type:" #type "=" #val)))
#define __type(type, val) __attribute__((btf_decl_tag("type:" #type "=" #val)))

#define BPF_F_CURRENT_CPU (-1)
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define BPF_MAP_TYPE_HASH 1

#define BPF_CORE_READ(dst) \
    ({ typeof(dst) val; bpf_probe_read(&val, sizeof(val), &dst); val; })

static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_get_current_comm)(char *buf, __u32 size_of_buf) = (void *)16;
static void *(*bpf_get_current_task)(void) = (void *)35;
static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *)25;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_probe_read)(void *dst, __u32 size, const void *src) = (void *)4;

char LICENSE[] SEC("license") = "GPL";

// Event structure to pass data to userspace
struct event
{
    __u32 pid;
    __u32 ppid;
    __u64 timestamp;
    char comm[16];
};

// Perf event map to send events to userspace
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

// Map to store target PID
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid_map SEC(".maps");

// Trace process execution
SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 key = 0;

    // Check if this is our target PID
    __u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!target_pid || *target_pid != pid)
    {
        return 0;
    }

    struct event e = {};
    e.pid = pid;
    e.timestamp = bpf_ktime_get_ns();

    // Get parent PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read(&e.ppid, sizeof(e.ppid), &parent->tgid);

    // Get process name
    bpf_get_current_comm(e.comm, sizeof(e.comm));

    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

// Trace process exits
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 key = 0;

    // Check if this is our target PID
    __u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!target_pid || *target_pid != pid)
    {
        return 0;
    }

    struct event e = {};
    e.pid = pid;
    e.timestamp = bpf_ktime_get_ns();

    // Get parent PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read(&e.ppid, sizeof(e.ppid), &parent->tgid);

    // Get process name
    bpf_get_current_comm(e.comm, sizeof(e.comm));

    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}
