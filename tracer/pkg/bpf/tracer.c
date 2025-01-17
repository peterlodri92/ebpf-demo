#include "tracer.h"

char LICENSE[] SEC("license") = "GPL";

// Maps definition using the macro
BPF_MAP(events, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, 1024);
BPF_MAP(target_pid_map, BPF_MAP_TYPE_HASH, __u32, __u32, 1);

struct syscall_enter_args
{
    __u64 pad;
    long id;
    unsigned long args[6];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct syscall_enter_args *ctx)
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

    // Get syscall ID directly from tracepoint context
    e.syscall_id = ctx->id;

    // Check if we should filter by PID
    __u32 key = 0;
    __u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);

    // Output first event from any process for debugging
    static __u32 first_event = 0;
    if (!first_event)
    {
        first_event = 1;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
        return 0;
    }

    // Only output events from target PID
    if (target_pid && *target_pid == pid)
    {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    }
    return 0;
}
