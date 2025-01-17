#include "tracer.h"

char LICENSE[] SEC("license") = "GPL";

// Maps definition using the macro
BPF_MAP(events, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, 1024);
BPF_MAP(target_pid_map, BPF_MAP_TYPE_HASH, __u32, __u32, 1);

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct event e = {};
    e.pid = pid;
    e.timestamp = bpf_ktime_get_ns();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    struct task_struct *parent;
    if (bpf_probe_read(&parent, sizeof(parent), &task->real_parent))
        return 0;

    if (bpf_probe_read(&e.ppid, sizeof(e.ppid), &parent->tgid))
        return 0;

    bpf_get_current_comm(e.comm, sizeof(e.comm));

    // Only emit events for python processes
    if (e.comm[0] != 'p' && e.comm[0] != 'u') // python/python3 or uvicorn
        return 0;
    if (e.comm[1] != 'y' && e.comm[1] != 'v') // python/python3 or uvicorn
        return 0;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 key = 0;

    struct event e = {};
    e.pid = pid;
    e.timestamp = bpf_ktime_get_ns();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    struct task_struct *parent;
    if (bpf_probe_read(&parent, sizeof(parent), &task->real_parent))
        return 0;

    if (bpf_probe_read(&e.ppid, sizeof(e.ppid), &parent->tgid))
        return 0;

    bpf_get_current_comm(e.comm, sizeof(e.comm));

    // Only emit events for python processes
    if (e.comm[0] != 'p' && e.comm[0] != 'u') // python/python3 or uvicorn
        return 0;
    if (e.comm[1] != 'y' && e.comm[1] != 'v') // python/python3 or uvicorn
        return 0;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}
