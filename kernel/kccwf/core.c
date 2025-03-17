#include "core.h"
#include "encoding.h"
#include "linux/atomic/atomic-long.h"
#include "linux/kccwf.h"
#include "linux/kern_levels.h"
#include "linux/printk.h"
#include "utils.h"

static atomic_long_t read_watchpoints[REAL_NUM_WATCHPOINTS];
static atomic_long_t write_watchpoints[REAL_NUM_WATCHPOINTS];

static atomic_t may_race_pair_trigger_flag = ATOMIC_INIT(0);
static atomic_t validate_race_pair_trigger_flag = ATOMIC_INIT(0);
atomic_long_t kccwf_read_count = ATOMIC_INIT(0);
atomic_long_t kccwf_write_count = ATOMIC_INIT(0);

atomic_long_t time_condition_check_total = ATOMIC_LONG_INIT(0);
atomic_long_t count_condition_check = ATOMIC_LONG_INIT(0);
atomic_long_t time_preparing_stage = ATOMIC_LONG_INIT(0);
atomic_long_t count_preparing_stage = ATOMIC_LONG_INIT(0);
atomic_long_t time_watchpoint_processing_total = ATOMIC_LONG_INIT(0);
atomic_long_t count_watchpoint_processing_total = ATOMIC_LONG_INIT(0);

DEFINE_READ_INSTRUMENTED_MEMORY(8)
DEFINE_READ_INSTRUMENTED_MEMORY(16)
DEFINE_READ_INSTRUMENTED_MEMORY(32)
DEFINE_READ_INSTRUMENTED_MEMORY(64)
static __always_inline u64 read_instrumented_memory(const volatile void *addr, int type)
{
	switch ((type >> 28) & 0xf) {
	case 1:
		return read_instrumented_memory8(addr);
	case 2:
		return read_instrumented_memory16(addr);
	case 4:
		return read_instrumented_memory32(addr);
	case 8:
		return read_instrumented_memory64(addr);
	default:
		return *(volatile u8 *)(uintptr_t)addr;
	}
}

DEFINE_FIND_WATCHPOINT_FUNCTION(find_write_watchpoint, write_watchpoints)
DEFINE_FIND_WATCHPOINT_FUNCTION(find_read_watchpoint, read_watchpoints)

DEFINE_INSERT_WATCHPOINT_FUNCTION(insert_read_watchpoint, read_watchpoints)
DEFINE_INSERT_WATCHPOINT_FUNCTION(insert_write_watchpoint, write_watchpoints)

// 将其设置为 CONSUMED_VALUE 并返回其原来的值
static __always_inline long consume_watchpoint(atomic_long_t *watchpoint)
{
	return atomic_long_xchg_relaxed(watchpoint, CONSUMED_VALUE);
}

static __always_inline void remove_watchpoint(atomic_long_t *watchpoint)
{
	if (KCCWF_DEBUG) {
		unsigned long addr_masked;
		size_t size;
		long encoded_wp = atomic_long_read(watchpoint);
		decode_watchpoint(encoded_wp, &addr_masked, &size);
		printk(KERN_INFO "remove read: var_addr %lx int tid %d\n",addr_masked,current->pid);
	}
	atomic_long_set(watchpoint, INVALID_VALUE);	
}

static __always_inline bool try_consume_watchpoint(atomic_long_t *watchpoint, long found_addr)
{
	return atomic_long_try_cmpxchg_relaxed(watchpoint, &found_addr,
					       CONSUMED_VALUE);
}

DEFINE_SETUP_WATCHPOINT_FUNCTION(read, read_watchpoints)
DEFINE_SETUP_WATCHPOINT_FUNCTION(write, write_watchpoints)

DEFINE_FOUND_WATCHPOINT_FUNCTION(read, read_watchpoints)
DEFINE_FOUND_WATCHPOINT_FUNCTION(write, write_watchpoints)

unsigned long get_current_thread_hash(pid_t tid)
{
	unsigned long hash = 0;
	thread_chain_t *tc, *tmp;
	func_call_t *fc;
	spin_lock_irqsave(&thread_chain_lock, thread_chain_lock_flags);
	list_for_each_entry_safe(tc, tmp, &global_thread_chain_head, list) {
		if (tc->tid == tid) {
			hash = tc->thread_call_stack_hash;
			break;
		}
	}
	spin_unlock_irqrestore(&thread_chain_lock, thread_chain_lock_flags);
	return hash;
}

atomic_long_t heap_count;
atomic_long_t stack_count;

/* is the addr in stack */
static __always_inline int is_stack_pointer(unsigned long addr)
{
	unsigned long irq_stack_start =
		(unsigned long)per_cpu(pcpu_hot.hardirq_stack_ptr,
				       raw_smp_processor_id()) +
		8 - IRQ_STACK_SIZE;
	unsigned long irq_stack_end = irq_stack_start + IRQ_STACK_SIZE;
	unsigned long stack_start = (unsigned long)current->stack;
	unsigned long stack_end = stack_start + THREAD_SIZE;
	return (addr >= irq_stack_start && addr < irq_stack_end) ||
	       (addr >= stack_start && addr < stack_end);
}
/* if the var in the may_race pairs it will get the delay time of corresponding struct and if it has same context(call_stack) with the ,it will get the double delay time of this*/
static __always_inline int get_delay_time(unsigned long target, unsigned long call_stack_hash)
{
	int left = 0;
	int right = 255;
	int result = 0;

	while (left <= right) {
		int mid = left + (right - left) / 2;
		if (global_validate_delay[mid].var_name == target && target != 0) {
			// 先检查当前 mid 的 call_stack_hash
			if (global_validate_delay[mid].call_stack_hash == call_stack_hash) {
				printk(KERN_INFO "Found var_name %lu and call_stack_hash %lu\n", target, call_stack_hash);
				return 2 * global_validate_delay[mid].delay_time;
			}
	
			// 向左遍历所有相同 var_name 的条目
			int i = mid - 1;
			while (i >= left && global_validate_delay[i].var_name == target) {
				if (global_validate_delay[i].call_stack_hash == call_stack_hash) {
					printk(KERN_INFO "Found var_name %lu and call_stack_hash %lu\n", target, call_stack_hash);
					return 2 * global_validate_delay[i].delay_time;
				}
				i--;
			}
	
			// 向右遍历所有相同 var_name 的条目
			int j = mid + 1;
			while (j <= right && global_validate_delay[j].var_name == target) {
				if (global_validate_delay[j].call_stack_hash == call_stack_hash) {
					printk(KERN_INFO "Found var_name %lu and call_stack_hash %lu\n", target, call_stack_hash);
					return 2 * global_validate_delay[j].delay_time;
				}
				j++;
			}
	
			// 如果所有相同 var_name 的条目均未匹配 call_stack_hash
			// 返回第一个找到的 var_name 的 delay_time（例如 mid 的位置）
			// printk(KERN_INFO "Found var_name %lu but not call_stack_hash %lu\n", target, call_stack_hash);
			if(KCCWF_DEBUG) 
				printk(KERN_INFO "Found var_name %lu but not call_stack_hash %lu\n", target, call_stack_hash);
			return 520;
	
		} else if (global_validate_delay[mid].var_name < target) {
			left = mid + 1;
		} else {
			right = mid - 1;
		}
	}

	return 0;
}

static __always_inline void log_access_info_ftrace(const access_info_t *var_access_info)
{
    trace_printk("Access info:  %p,  %d,  %lu,  %d,  %d,  %lu,  %d,  %lu,  %d,  %d\n",
                 var_access_info->var_addr, var_access_info->is_write, var_access_info->var_name, var_access_info->file_line, var_access_info->type, var_access_info->access_time, var_access_info->tid, var_access_info->call_stack_hash, var_access_info->delay_time, var_access_info->is_skip);
}

void rec_mem_access(const volatile void *addr, unsigned long var_name,
	int is_write, int file_line, int type)
{
	ktime_t start, end;
	u64 delta;
	unsigned long irq_flags = 0;
	local_irq_save(irq_flags);

	// condition checking part
	if(TIME_MEASUREMENT) start = ktime_get();
	if (current->kccwf_disable_count || !addr) {
		goto exit_label;
	}
	if (is_stack_pointer((unsigned long)addr)) {
		if (KCCWF_DEBUG) atomic_long_inc(&stack_count);
		goto exit_label;
	}else {
		if (KCCWF_DEBUG) atomic_long_inc(&heap_count);
	}
	if (is_write) {
		if (KCCWF_DEBUG) atomic_long_inc(&kccwf_write_count);
	} else {
		if (KCCWF_DEBUG) atomic_long_inc(&kccwf_read_count);
	}
	if(TIME_MEASUREMENT){
		end = ktime_get();
		delta = ktime_to_ns(ktime_sub(end, start));
		atomic_long_add(delta, &time_condition_check_total);
		atomic_long_inc(&count_condition_check);
	}

	// preparation stage
	if (TIME_MEASUREMENT) start = ktime_get();
	ktime_t access_time = ktime_get();
	pid_t tid = current->pid;
	unsigned long call_stack_hash = get_current_thread_hash(tid);

	int delay_time = get_delay_time(var_name, call_stack_hash);
	if (!delay_time && IS_RANDOM_ENABLED(kccwf_mode)) {
		if (get_random_u32_below(1000) < DELAY_PROBABILITY) {
			delay_time = 80;
		}
	} else {
		delay_time = 0;
	}
	access_info_t var_access_info = { 
		.is_write = is_write,
		.file_line = file_line,
		.var_name = var_name,
		.type = type,
		.var_addr = addr,
		.call_stack_hash = call_stack_hash,
		.access_time = access_time,
		.tid = tid,
		.delay_time = delay_time,
		.is_skip = 0 
	};
	if (TIME_MEASUREMENT){
		end = ktime_get();
		delta = ktime_to_ns(ktime_sub(end, start));
		atomic_long_add(delta, &time_preparing_stage);
		atomic_long_inc(&count_preparing_stage);
	}

	// 测量观察点处理
	if(TIME_MEASUREMENT) start = ktime_get();
	if (IS_LOG_ENABLED(kccwf_mode)) {
		// log_access_info(&var_access_info);
		log_access_info_ftrace(&var_access_info);
	}
	atomic_long_t *watchpoint;
	long found_addr;
	if (KCCWF_DEBUG) {
		printk(KERN_INFO "rec_mem_access: var_addr %lx int tid %d\n",(unsigned long)var_access_info.var_addr,tid);
	}
	if (is_write) {
		watchpoint = find_write_watchpoint(&var_access_info, &found_addr);
		if (watchpoint) {
			if (KCCWF_DEBUG) {
				printk(KERN_INFO "found write: var_addr %lx int tid %d\n",(unsigned long)var_access_info.var_addr,tid);
			}
			found_write_watchpoint(&var_access_info, watchpoint, found_addr);
		} else {
			watchpoint = find_read_watchpoint(&var_access_info, &found_addr);
			if (watchpoint) {
				found_read_watchpoint(&var_access_info, watchpoint, found_addr);
			} else {
				if (KCCWF_DEBUG) {
					printk(KERN_INFO "set write: var_addr %lx int tid %d\n",(unsigned long)var_access_info.var_addr,tid);
				}
				setup_write_watchpoint(&var_access_info);
			}
		}
	} else {
		watchpoint = find_write_watchpoint(&var_access_info, &found_addr);
		if (watchpoint) {
			if (KCCWF_DEBUG) {
				printk(KERN_INFO "found read: var_addr %lx int tid %d\n",(unsigned long)var_access_info.var_addr,tid);
			}
			found_write_watchpoint(&var_access_info, watchpoint, found_addr);
		} else {
			if (KCCWF_DEBUG) {
				printk(KERN_INFO "set read: var_addr %lx int tid %d\n",(unsigned long)var_access_info.var_addr,tid);
			}
			setup_read_watchpoint(&var_access_info);
		}
	}
	if(TIME_MEASUREMENT){
		end = ktime_get();
		delta = ktime_to_ns(ktime_sub(end, start));
		atomic_long_add(delta, &time_watchpoint_processing_total);
		atomic_long_inc(&count_watchpoint_processing_total);
	}
exit_label:
	local_irq_restore(irq_flags);
}
EXPORT_SYMBOL(rec_mem_access);

void enable_kccwf_free_rec(void){
	current->kccwf_free_enable_count++;
}
EXPORT_SYMBOL(enable_kccwf_free_rec);

void disable_kccwf_free_rec(void){
	current->kccwf_free_enable_count--;
}
EXPORT_SYMBOL(disable_kccwf_free_rec);