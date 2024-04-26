// SPDX-License-Identifier: (GPL-2.0 OR Apache-2.0)

#include <linux/version.h>

#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 12, 0))
#define BPF_PERF_EVENT_READ_VALUE_AVAILABLE 1
#endif

#include "kepler.bpf.h"

// processes and pid time
BPF_HASH(processes, __u32, process_metrics_t);
BPF_HASH(pid_time, __u32, __u64);

// perf counters
BPF_PERF_ARRAY(cpu_cycles_event_reader);
BPF_ARRAY(cpu_cycles, __u64);

BPF_PERF_ARRAY(cpu_ref_cycles_event_reader);
BPF_ARRAY(cpu_ref_cycles, __u64);

BPF_PERF_ARRAY(cpu_instructions_event_reader);
BPF_ARRAY(cpu_instructions, __u64);

BPF_PERF_ARRAY(cache_miss_event_reader);
BPF_ARRAY(cache_miss, __u64);

BPF_PERF_ARRAY(task_clock_ms_event_reader);
BPF_ARRAY(task_clock, __u64);

// cpu freq counters
BPF_ARRAY(cpu_freq_array, __u32);

// setting sample rate or counter to 0 will make compiler to remove the code
// entirely.
int sample_rate = 1;
int counter_sched_switch = 0;

static inline __u64 get_on_cpu_time(__u32 cur_pid, __u32 prev_pid,
                                    __u64 cur_ts) {
  __u64 cpu_time = 0;

  // get pid time
  pid_time_t prev_pid_key = {.pid = prev_pid};
  __u64 *prev_ts;
  prev_ts = bpf_map_lookup_elem(&pid_time, &prev_pid_key);
  if (prev_ts) {
    // Probably a clock issue where the recorded on-CPU event had a
    // timestamp later than the recorded off-CPU event, or vice versa.
    if (cur_ts > *prev_ts) {
      cpu_time = (cur_ts - *prev_ts) / 1000000; // convert to ms
      bpf_map_delete_elem(&pid_time, &prev_pid_key);
    }
  }
  pid_time_t new_pid_key = {.pid = cur_pid};
  bpf_map_update_elem(&pid_time, &new_pid_key, &cur_ts, BPF_NOEXIST);
  return cpu_time;
}

static inline __u64 calc_delta(__u64 *prev_val, __u64 *val) {
  __u64 delta = 0;
  if (prev_val) {
    if (*val > *prev_val)
      delta = *val - *prev_val;
  }
  return delta;
}

static inline __u64 get_on_cpu_task_clock_time(__u32 *cpu_id, __u64 cur_ts) {
  __u64 delta = 0;
#ifdef BPF_PERF_EVENT_READ_VALUE_AVAILABLE
  struct bpf_perf_event_value c = {};
  int error =
      bpf_perf_event_read_value(&task_clock_ms_event_reader, *cpu_id, &c,
                                sizeof(struct bpf_perf_event_value));
  if (error == 0) {
    __u64 val = c.counter;
    __u64 *prev_val = bpf_map_lookup_elem(&task_clock, cpu_id);
    delta = calc_delta(prev_val, &val);
    bpf_map_update_elem(&task_clock, cpu_id, &val, BPF_ANY);
  }
#else
  int ret = bpf_perf_event_read(&task_clock_ms_event_reader, *cpu_id);
  if (ret < 0) {
    return delta;
  }
  __u64 val = ret;
  __u64 *prev_val = bpf_map_lookup_elem(&task_clock, cpu_id);
  delta = calc_delta(prev_val, &val);
  bpf_map_update_elem(&task_clock, cpu_id, &val, BPF_ANY);
#endif

  return delta / 1000000; // convert to ms
}
// although the "get_on_cpu_counters" has some code duplications, it is inline
// code and the compiles will improve this
static inline __u64 get_on_cpu_cycles(__u32 *cpu_id) {
  __u64 delta = 0;
#ifdef BPF_PERF_EVENT_READ_VALUE_AVAILABLE
  struct bpf_perf_event_value c = {};
  int error = bpf_perf_event_read_value(&cpu_cycles_event_reader, *cpu_id, &c,
                                        sizeof(struct bpf_perf_event_value));
  if (error == 0) {
    __u64 val = c.counter;
    __u64 *prev_val = bpf_map_lookup_elem(&cpu_cycles, cpu_id);
    delta = calc_delta(prev_val, &val);
    bpf_map_update_elem(&cpu_cycles, cpu_id, &val, BPF_ANY);
  }
#else
  int ret = bpf_perf_event_read(&cpu_cycles_event_reader, *cpu_id);
  if (ret < 0) {
    return delta;
  }
  __u64 val = ret;
  __u64 *prev_val = bpf_map_lookup_elem(&cpu_cycles, cpu_id);
  delta = calc_delta(prev_val, &val);
  bpf_map_update_elem(&cpu_cycles, cpu_id, &val, BPF_ANY);
#endif

  return delta;
}

static inline __u64 get_on_cpu_ref_cycles(__u32 *cpu_id) {
  __u64 delta = 0;
#ifdef BPF_PERF_EVENT_READ_VALUE_AVAILABLE
  struct bpf_perf_event_value c = {};
  int error =
      bpf_perf_event_read_value(&cpu_ref_cycles_event_reader, *cpu_id, &c,
                                sizeof(struct bpf_perf_event_value));
  if (error == 0) {
    __u64 val = c.counter;
    __u64 *prev_val = bpf_map_lookup_elem(&cpu_ref_cycles, cpu_id);
    delta = calc_delta(prev_val, &val);
    bpf_map_update_elem(&cpu_ref_cycles, cpu_id, &val, BPF_ANY);
  }
#else
  int ret = bpf_perf_event_read(&cpu_ref_cycles_event_reader, *cpu_id);
  if (ret < 0) {
    return delta;
  }
  __u64 val = ret;
  __u64 *prev_val = bpf_map_lookup_elem(&cpu_ref_cycles, cpu_id);
  delta = calc_delta(prev_val, &val);
  bpf_map_update_elem(&cpu_ref_cycles, cpu_id, &val, BPF_ANY);
#endif
  return delta;
}

static inline __u64 get_on_cpu_instr(__u32 *cpu_id) {
  __u64 delta = 0;
#ifdef BPF_PERF_EVENT_READ_VALUE_AVAILABLE
  struct bpf_perf_event_value c = {};
  int error =
      bpf_perf_event_read_value(&cpu_instructions_event_reader, *cpu_id, &c,
                                sizeof(struct bpf_perf_event_value));
  if (error == 0) {
    __u64 val = c.counter;
    __u64 *prev_val = bpf_map_lookup_elem(&cpu_instructions, cpu_id);
    delta = calc_delta(prev_val, &val);
    bpf_map_update_elem(&cpu_instructions, cpu_id, &val, BPF_ANY);
  }
#else
  int ret = bpf_perf_event_read(&cpu_instructions_event_reader, *cpu_id);
  if (ret < 0) {
    return delta;
  }
  __u64 val = ret;
  __u64 *prev_val = bpf_map_lookup_elem(&cpu_instructions, cpu_id);
  delta = calc_delta(prev_val, &val);
  bpf_map_update_elem(&cpu_instructions, cpu_id, &val, BPF_ANY);
#endif
  return delta;
}

static inline __u64 get_on_cpu_cache_miss(__u32 *cpu_id) {
  __u64 delta = 0;
#ifdef BPF_PERF_EVENT_READ_VALUE_AVAILABLE
  struct bpf_perf_event_value c = {};
  int error = bpf_perf_event_read_value(&cache_miss_event_reader, *cpu_id, &c,
                                        sizeof(struct bpf_perf_event_value));
  if (error == 0) {
    __u64 val = c.counter;
    __u64 *prev_val = bpf_map_lookup_elem(&cache_miss, cpu_id);
    delta = calc_delta(prev_val, &val);
    bpf_map_update_elem(&cache_miss, cpu_id, &val, BPF_ANY);
  }
#else
  int ret = bpf_perf_event_read(&cache_miss_event_reader, *cpu_id);
  if (ret < 0) {
    return delta;
  }
  __u64 val = ret;
  __u64 *prev_val = bpf_map_lookup_elem(&cache_miss, cpu_id);
  delta = calc_delta(prev_val, &val);
  bpf_map_update_elem(&cache_miss, cpu_id, &val, BPF_ANY);
#endif
  return delta;
}

// calculate the average cpu freq
static inline __u64 get_on_cpu_avg_freq(__u32 *cpu_id,
                                        __u64 on_cpu_cycles_delta,
                                        __u64 on_cpu_ref_cycles_delta) {
  __u32 avg_freq = 0;
  bpf_map_lookup_or_try_init(&cpu_freq_array, cpu_id, &avg_freq);
  if (avg_freq == 0) {
    avg_freq =
        ((on_cpu_cycles_delta * CPU_REF_FREQ) / on_cpu_ref_cycles_delta) * HZ;
  } else {
    avg_freq +=
        ((on_cpu_cycles_delta * CPU_REF_FREQ) / on_cpu_ref_cycles_delta) * HZ;
    avg_freq /= 2;
  }
  bpf_map_update_elem(&cpu_freq_array, cpu_id, &avg_freq, BPF_ANY);
  return avg_freq;
}

SEC("kprobe/finish_task_switch")
int BPF_KPROBE(finish_task_switch, struct task_struct *prev_task) {
  // only do sampling if sample rate is set
  if (sample_rate != 0) {
    if (counter_sched_switch > 0) {
      counter_sched_switch--;
      return 0;
    }
    counter_sched_switch = sample_rate;
  }

  // Getting the PID of the scheduled-out task
  __u64 prev_tgid = BPF_CORE_READ(prev_task, tgid);
  __u32 prev_pid = BPF_CORE_READ(prev_task, pid);

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 cur_pid = pid_tgid & 0xffffffff;
  __u32 tgid = pid_tgid >> 32;
  __u64 cgroup_id = bpf_get_current_cgroup_id();
  __u32 cpu_id = bpf_get_smp_processor_id();
  __u64 cur_ts = bpf_ktime_get_ns();
  __u64 on_cpu_cycles_delta = get_on_cpu_cycles(&cpu_id);
  __u64 on_cpu_ref_cycles_delta = get_on_cpu_ref_cycles(&cpu_id);
  __u64 on_cpu_instr_delta = get_on_cpu_instr(&cpu_id);
  __u64 on_cpu_cache_miss_delta = get_on_cpu_cache_miss(&cpu_id);
  __u64 on_cpu_avg_freq = get_on_cpu_avg_freq(&cpu_id, on_cpu_cycles_delta,
                                              on_cpu_ref_cycles_delta);
  __u64 on_cpu_time_delta = get_on_cpu_time(cur_pid, prev_pid, cur_ts);
  __u64 on_task_clock_time_delta = get_on_cpu_task_clock_time(&cpu_id, cur_ts);

  struct process_metrics_t *process_metrics;
  process_metrics = bpf_map_lookup_elem(&processes, &prev_pid);
  if (process_metrics) {
    // update process time
    process_metrics->process_run_time += on_cpu_time_delta;
    process_metrics->task_clock_time += on_task_clock_time_delta;
    process_metrics->cpu_cycles += on_cpu_cycles_delta;
    process_metrics->cpu_instr += on_cpu_instr_delta;
    process_metrics->cache_miss += on_cpu_cache_miss_delta;
  }

  // creat new process metrics
  process_metrics = bpf_map_lookup_elem(&processes, &cur_pid);
  if (process_metrics == 0) {
    process_metrics_t new_process = {};
    new_process.pid = cur_pid;
    new_process.tgid = tgid;
    new_process.cgroup_id = cgroup_id;
    // bpf_probe_read(&new_process.comm, sizeof(new_process.comm), (void
    // *)ctx->next_comm);
    bpf_get_current_comm(&new_process.comm, sizeof(new_process.comm));
    bpf_map_update_elem(&processes, &cur_pid, &new_process, BPF_NOEXIST);
  }

  return 0;
}

SEC("tracepoint/irq/softirq_entry")
int kepler_irq_trace(struct trace_event_raw_softirq *ctx) {
  __u32 cur_pid = bpf_get_current_pid_tgid();
  struct process_metrics_t *process_metrics;
  unsigned int vec = ctx->vec;
  process_metrics = bpf_map_lookup_elem(&processes, &cur_pid);
  if (process_metrics != 0) {
    if (vec < IRQ_MAX_LEN) {
      __u16 count = process_metrics->vec_nr[vec];
      count++;
      process_metrics->vec_nr[vec] = count;
    }
  }
  return 0;
}

// count read page cache
SEC("kprobe/mark_page_accessed")
int kprobe__mark_page_accessed(struct pt_regs *ctx) {
  __u32 cur_pid = bpf_get_current_pid_tgid();
  struct process_metrics_t *process_metrics;
  process_metrics = bpf_map_lookup_elem(&processes, &cur_pid);
  if (process_metrics) {
    process_metrics->page_cache_hit++;
  }
  return 0;
}

// count write page cache
SEC("kprobe/set_page_dirty")
int kprobe__set_page_dirty(struct pt_regs *ctx) {
  __u32 cur_pid = bpf_get_current_pid_tgid();
  struct process_metrics_t *process_metrics;
  process_metrics = bpf_map_lookup_elem(&processes, &cur_pid);
  if (process_metrics) {
    process_metrics->page_cache_hit++;
  }
  return 0;
}

char _license[] SEC("license") = "GPL";
