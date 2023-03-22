#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/libbpf_common.h>

char LICENSE[] SEC("license") = "GPL";

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u64);
  __type(value, u64);
} xx SEC(".maps");

SEC("perf_event")
int sys_enter(struct bpf_perf_event_data *ctx)
{
  u32 key = bpf_get_smp_processor_id();
  struct bpf_perf_event_value buf;
  bpf_perf_event_read_value(ctx, key, &buf, sizeof(buf));
  bpf_printk("counter: %d enabled: %d running: %d\n", buf.counter, buf.enabled, buf.running);
  return 0;
}