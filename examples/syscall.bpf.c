#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/libbpf_common.h>
#include "maps.bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u64);
  __type(value, u64);
} syscall_map SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx)
{
  // bpf_printk("pid=%d syscall=%d", pid, ctx->id);
  char comm[16];
  bpf_get_current_comm(comm, sizeof(comm));
  u32 cpu = bpf_get_smp_processor_id();
  bpf_printk("comm: %s, cpu: %d", comm, cpu); // That might help
  u64 syscall_id = (u64)ctx->id;
  increment_map(&syscall_map, &syscall_id, 1);
  return 0;
}