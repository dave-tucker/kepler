/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef __KEPLER_H__
#define __KEPLER_H__

#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 * see
 * https://github.com/iovisor/bcc/commit/2d1497cde1cc9835f759a707b42dea83bee378b8
 * for more details
 */
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#ifndef NUM_CPUS
#define NUM_CPUS 128
#endif

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// irq counter, 10 is the max number of irq vectors
#ifndef IRQ_MAX_LEN
#define IRQ_MAX_LEN 10
#endif

#ifndef CPU_REF_FREQ
#define CPU_REF_FREQ 2500
#endif

#ifndef HZ
#define HZ 1000
#endif

#ifndef MAP_SIZE
#define MAP_SIZE 32768
#endif

// array size is to be reset in userspace
#define BPF_ARRARY_MAP(_name, _type, _key_type, _value_type)                   \
  struct {                                                                     \
    __uint(type, _type);                                                       \
    __type(key, _key_type);                                                    \
    __type(value, _value_type);                                                \
    __uint(max_entries, NUM_CPUS);                                             \
  } _name SEC(".maps");

#define BPF_HASH(_name, _key_type, _value_type)                                \
  struct {                                                                     \
    __uint(type, BPF_MAP_TYPE_HASH);                                           \
    __type(key, _key_type);                                                    \
    __type(value, _value_type);                                                \
    __uint(max_entries, MAP_SIZE);                                             \
  } _name SEC(".maps");

#define BPF_ARRAY(_name, _leaf_type)                                           \
  BPF_ARRARY_MAP(_name, BPF_MAP_TYPE_ARRAY, __u32, _leaf_type);

#define BPF_PERF_ARRAY(_name)                                                  \
  BPF_ARRARY_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32)

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init) {
  void *val;
  int err;

  val = bpf_map_lookup_elem(map, key);
  if (val)
    return val;

  err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
  if (err && err != -17)
    return 0;

  return bpf_map_lookup_elem(map, key);
}

struct sched_switch_args {
  unsigned long long pad;
  char prev_comm[TASK_COMM_LEN];
  int prev_pid;
  int prev_prio;
  long long prev_state;
  char next_comm[TASK_COMM_LEN];
  int next_pid;
  int next_prio;
};

struct trace_event_raw_softirq {
  unsigned long long pad;
  unsigned int vec;
};

typedef struct process_metrics_t {
  __u64 cgroup_id;
  __u64 pid;  // pid is the kernel space view of the thread id
  __u64 tgid; // tgid is the user space view of the pid
  __u64 process_run_time;
  __u64 task_clock_time;
  __u64 cpu_cycles;
  __u64 cpu_instr;
  __u64 cache_miss;
  __u64 page_cache_hit;
  __u16 vec_nr[IRQ_MAX_LEN];
  char comm[TASK_COMM_LEN];
} process_metrics_t;

typedef struct pid_time_t {
  __u32 pid;
} pid_time_t;

struct task_struct {
  __u64 tgid;
  __u32 pid;
} __attribute__((preserve_access_index));

#if defined(bpf_target_x86) // x86
struct pt_regs {
  unsigned long r15;
  unsigned long r14;
  unsigned long r13;
  unsigned long r12;
  unsigned long rbp;
  unsigned long rbx;
  unsigned long r11;
  unsigned long r10;
  unsigned long r9;
  unsigned long r8;
  unsigned long rax;
  unsigned long rcx;
  unsigned long rdx;
  unsigned long rsi;
  unsigned long rdi;
  unsigned long orig_rax;
  unsigned long rip;
  unsigned long cs;
  unsigned long eflags;
  unsigned long rsp;
  unsigned long ss;
};
#endif // defined(bpf_target_x86)

#if defined(bpf_target_arm64) // arm64
struct user_pt_regs {
  __u64 regs[31];
  __u64 sp;
  __u64 pc;
  __u64 pstate;
};

#endif // defined(bpf_target_arm64)

#if defined(bpf_target_s390) // s390

typedef struct {
  unsigned long mask;
  unsigned long addr;
} __attribute__((aligned(8))) psw_t;

typedef struct {
  unsigned long args[1];
  psw_t psw;
  unsigned long gprs[16];
} user_pt_regs;

#endif // defined(bpf_target_s390)

#endif // __KEPLER_H__
