/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"

#ifndef __PROFILE_H_
#define __PROFILE_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 16
#endif

typedef u64 stack_trace_t[MAX_STACK_DEPTH];

struct stacktrace_event
{
  u32 pid;
  u32 cpu_id;
  char comm[TASK_COMM_LEN];
  s32 kstack_sz;
  s32 ustack_sz;
  stack_trace_t kstack;
  stack_trace_t ustack;
};

#endif /* __PROFILE_H_ */
