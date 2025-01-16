// tracer.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

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
    e.ppid = BPF_CORE_READ(task, real_parent, tgid);

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
    e.ppid = BPF_CORE_READ(task, real_parent, tgid);

    // Get process name
    bpf_get_current_comm(e.comm, sizeof(e.comm));

    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}
