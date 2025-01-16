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
    __u32 key = 0;

    __u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!target_pid || *target_pid != pid)
        return 0;

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

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 key = 0;

    __u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!target_pid || *target_pid != pid)
        return 0;

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
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}