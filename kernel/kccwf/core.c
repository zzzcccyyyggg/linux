#include "core.h"
#include "encoding.h"
#include "linux/atomic/atomic-instrumented.h"
#include "linux/kccwf.h"
#include "linux/printk.h"
#include "linux/types.h"



/* global variable */
kccwf_statistical_var_t kccwf_statistical_var;
kccwf_current_t kccwf_current;
atomic64_t *kccwf_read_access_infos_sn;
kccwf_write_access_buffer_t kccwf_write_access_buffer;


/* global variable */

/* static global variable */
static atomic_long_t read_watchpoints[REAL_NUM_WATCHPOINTS];
static atomic_long_t write_watchpoints[REAL_NUM_WATCHPOINTS];
/* static global variable */

/* function declare */
DEFINE_FIND_WATCHPOINT_FUNCTION(find_write_watchpoint, write_watchpoints)
DEFINE_FIND_WATCHPOINT_FUNCTION(find_read_watchpoint, read_watchpoints)

DEFINE_INSERT_WATCHPOINT_FUNCTION(insert_read_watchpoint, read_watchpoints)
DEFINE_INSERT_WATCHPOINT_FUNCTION(insert_write_watchpoint, write_watchpoints)
/* function declare */

inline int kccwf_core_init(void){
    current->kccwf_disable_count++;
    kccwf_read_access_infos_sn = vzalloc(sizeof(atomic64_t) * KCCWF_MAX_READ_ACCESS_INFOS);
    if (!kccwf_read_access_infos_sn){
		printk(KERN_ERR "Failed to allocate memory for kccwf_read_access_infos_sn\n");
		goto fail_exit;
    }

	kccwf_write_access_buffer.kccwf_write_access_buffer = vzalloc(sizeof(write_access_info_t) * KCCWF_MAX_WRITE_ACCESS_INFOS);
	if (!kccwf_write_access_buffer.kccwf_write_access_buffer){
		printk(KERN_ERR "Failed to allocate memory for kccwf_write_access_buffer\n");
		goto fail_exit;
    }
	raw_spin_lock_init(&kccwf_write_access_buffer.kccwf_write_access_buffer_lock);
	kccwf_concurrent_pairs_init(&kccwf_concurrent_pairs);

	atomic_set(&kccwf_current.kccwf_validate_times, 0); 
	kccwf_current.kccwf_mode = KCCWF_DISABLE_MODE;

    current->kccwf_disable_count--;
    return 0;
fail_exit:
	current->kccwf_disable_count--;
	return -ENOMEM;

}

inline void kccwf_core_exit(void){
	current->kccwf_disable_count++;
	vfree(kccwf_read_access_infos_sn);
	vfree(kccwf_write_access_buffer.kccwf_write_access_buffer);
	current->kccwf_disable_count--;
}

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

void kccwf_rec_mem_access(const volatile void *addr, unsigned long var_name,int is_write, int file_line, int size)
{
	ktime_t start, end;
	u64 delta;
	int delay_time = 0;
	access_info_t var_access_info;
	unsigned long irq_flags = 0;
	local_irq_save(irq_flags);

	// condition checking part
	if(TIME_MEASUREMENT) start = ktime_get();
	if (current->kccwf_disable_count || !addr || kccwf_current.kccwf_mode == KCCWF_DISABLE_MODE) {
		goto exit_label;
	}
	if (is_stack_pointer((unsigned long)addr)) {
		if (KCCWF_DEBUG) atomic_long_inc(&kccwf_statistical_var.stack_count);
		goto exit_label;
	}else {
		if (KCCWF_DEBUG) atomic_long_inc(&kccwf_statistical_var.heap_count);
	}
	if(TIME_MEASUREMENT){
		end = ktime_get();
		delta = ktime_to_ns(ktime_sub(end, start));
		atomic_long_add(delta, &kccwf_statistical_var.time_condition_check_total);
		atomic_long_inc(&kccwf_statistical_var.count_condition_check);
	}

	// preparation stage
	if (TIME_MEASUREMENT) start = ktime_get();

	// try the best to ensure order
	ktime_t access_time = ktime_get();
	unsigned long sn = (unsigned long)raw_atomic_long_fetch_inc(&kccwf_read_access_infos_sn[var_name % KCCWF_MAX_READ_ACCESS_INFOS]);
	pid_t tid = current->pid;
	smp_mb();
	if (TIME_MEASUREMENT){
		end = ktime_get();
		delta = ktime_to_ns(ktime_sub(end, start));
		atomic_long_add(delta, &kccwf_statistical_var.time_preparing_stage);
		atomic_long_inc(&kccwf_statistical_var.count_preparing_stage);
	}
	if(kccwf_current.kccwf_mode == KCCWF_MONITOR_MODE){
		if(get_random_u32_below(100) < DELAY_PROBABILITY){
            delay_time = get_random_u32_below(80);
        }else{
            delay_time = 0;
        }
		goto monitor;
	}
	// log part
	if (!is_write){
		if (KCCWF_DEBUG) atomic_long_inc(&kccwf_statistical_var.kccwf_read_count);
		read_access_info_t read_access_info = { 
			.var_name = var_name,
			.var_addr = addr,
			.access_time = access_time,
			.tid = tid,
			.size = size,
			.sn = sn,
			.file_line = file_line,
		};
		// [optimize me the following loop spend too much time, maybe we can use hash to improve it ] 不急 应该还好 主要的耗时还是在后面watchpoint的处理上
		if (kccwf_current.kccwf_mode == KCCWF_LOG_MODE){
			log_read_access(&read_access_info);
			goto exit_label;
		}else if(kccwf_current.kccwf_mode == KCCWF_VALIDATE_MODE){
			// pr_info("The kccwf_may_race_pairs num is %d\n",kccwf_may_race_pairs_num);

			if (atomic_read(&kccwf_current.kccwf_validate_times) > KCCWF_MAX_VALIDAE_TIMES){
				goto exit_label;
			}
			race_pair_t *may_race_pair = kmalloc(sizeof(race_pair_t), GFP_KERNEL);
			may_race_pair->read_name = var_name;
			may_race_pair->sn = sn;
			race_pair_entry_t *entry = kccwf_find_race_pair(&kccwf_concurrent_pairs.checked_race_list, 
														&kccwf_concurrent_pairs.checked_race_lock, 
														may_race_pair, 
														kccwf_race_pair_cmp_by_varname);
			if (entry){
				printk(KERN_INFO "The read_name %lu in sn %lu has validated\n",var_name,sn);
				goto exit_label;
			}
			entry = kccwf_find_race_pair(&kccwf_concurrent_pairs.may_race_list, 
				&kccwf_concurrent_pairs.may_race_lock, 
				may_race_pair, 
				kccwf_race_pair_cmp);
			if (entry){
				int validate_times = atomic_fetch_inc(&kccwf_current.kccwf_validate_times);
				// printk(KERN_INFO "The validate_times %d\n",validate_times);
				if (validate_times >= KCCWF_MAX_VALIDAE_TIMES){
					goto exit_label;
				}
				/* 插入到checked 并改变delay time */
				kccwf_add_checked_race_pair(&kccwf_concurrent_pairs,may_race_pair);
				delay_time = 1000000;
				printk(KERN_INFO "Validate read_name %lu in sn %lu\n",var_name,sn);
				goto monitor;
			}
		}
		
	}else {
		if (KCCWF_DEBUG) atomic_long_inc(&kccwf_statistical_var.kccwf_write_count);
		raw_spin_lock_irqsave(&kccwf_write_access_buffer.kccwf_write_access_buffer_lock, kccwf_write_access_buffer.kccwf_write_access_buffer_lockflags);
		// Ensure that the waiting queue is fully populated when running
		unsigned int _tail = (kccwf_write_access_buffer.kccwf_write_access_buffer_tail + 1); 
		kccwf_write_access_buffer.kccwf_write_access_buffer[_tail % KCCWF_MAX_WRITE_ACCESS_INFOS].access_time = ktime_get();
		kccwf_write_access_buffer.kccwf_write_access_buffer[_tail % KCCWF_MAX_WRITE_ACCESS_INFOS].tid = tid;
		kccwf_write_access_buffer.kccwf_write_access_buffer[_tail % KCCWF_MAX_WRITE_ACCESS_INFOS].var_addr = addr;
		kccwf_write_access_buffer.kccwf_write_access_buffer[_tail % KCCWF_MAX_WRITE_ACCESS_INFOS].size = size;
		smp_mb();
		kccwf_write_access_buffer.kccwf_write_access_buffer_tail = _tail;
		// printk(KERN_INFO "kccwf write,tail is %u\n",kccwf_write_access_buffer_tail);
		wake_up(&kccwf_access_twbuffer.wq);
		raw_spin_unlock_irqrestore(&kccwf_write_access_buffer.kccwf_write_access_buffer_lock, kccwf_write_access_buffer.kccwf_write_access_buffer_lockflags);
		delay_time = 0;
		goto monitor;
	}

	if (delay_time == 0){
		goto exit_label;
	}
monitor:
	// watch point processing part
	if (!is_write)
		start = ktime_get();
	// printk(KERN_INFO "watch point processing part \n");
	var_access_info.is_write = is_write;
	var_access_info.file_line = file_line;
	var_access_info.var_name = var_name;
	var_access_info.size = size;
	var_access_info.var_addr = addr;
	var_access_info.call_stack_hash = 0;
	var_access_info.access_time = access_time;
	var_access_info.delay_time = delay_time;
	var_access_info.is_skip = 0;

	if(TIME_MEASUREMENT) start = ktime_get();
	atomic_long_t *watchpoint;
	long found_addr;
	if (KCCWF_DEBUG) {
		printk(KERN_INFO "kccwf_rec_mem_access: var_addr %lx int tid %d\n",(unsigned long)addr,tid);
	}
	if (is_write) {
		// printk(KERN_INFO "kccwf_rec_mem_access: write var_addr %lx int tid %d\n",(unsigned long)addr,tid);
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
		// printk(KERN_INFO "kccwf_rec_mem_access: read var_addr %lx int tid %d\n",(unsigned long)addr,tid);
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
		atomic_long_add(delta, &kccwf_statistical_var.time_watchpoint_processing_total);
		atomic_long_inc(&kccwf_statistical_var.count_watchpoint_processing_total);
	}
	if (!is_write){
		end = ktime_get();
		delta = ktime_to_ns(ktime_sub(end, start));
		printk(KERN_INFO "kccwf_rec_mem_access: read var_addr %lx int tid %d\n",(unsigned long)addr,tid);
		printk(KERN_INFO "The total time is %lu and the delay time is %lu\n",delta,delay_time);
	}

exit_label:
	local_irq_restore(irq_flags);
}
EXPORT_SYMBOL(kccwf_rec_mem_access);

void enable_kccwf_free_rec(void){
	current->kccwf_free_enable_count++;
}
EXPORT_SYMBOL(enable_kccwf_free_rec);

void disable_kccwf_free_rec(void){
	current->kccwf_free_enable_count--;
}
EXPORT_SYMBOL(disable_kccwf_free_rec);