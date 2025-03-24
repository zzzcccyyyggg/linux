#include "core.h"
#include "asm-generic/barrier.h"
#include "encoding.h"
#include "linux/kccwf.h"
#include "linux/printk.h"
#include "linux/spinlock.h"
#include "linux/spinlock_types.h"


/* global variable */
// 统计变量
atomic_long_t kccwf_read_count = ATOMIC_INIT(0);
atomic_long_t kccwf_write_count = ATOMIC_INIT(0);


atomic_long_t heap_count;
atomic_long_t stack_count;

atomic_long_t time_condition_check_total = ATOMIC_LONG_INIT(0);
atomic_long_t count_condition_check = ATOMIC_LONG_INIT(0);
atomic_long_t time_preparing_stage = ATOMIC_LONG_INIT(0);
atomic_long_t count_preparing_stage = ATOMIC_LONG_INIT(0);
atomic_long_t time_watchpoint_processing_total = ATOMIC_LONG_INIT(0);
atomic_long_t count_watchpoint_processing_total = ATOMIC_LONG_INIT(0);
// 统计变量

atomic64_t *kccwf_read_access_infos_sn;
write_access_info_t *kccwf_write_access_buffer;
unsigned int kccwf_write_access_buffer_head;
unsigned int kccwf_write_access_buffer_tail;

race_pair_t *kccwf_may_race_pairs;
unsigned int kccwf_may_race_pairs_num;

race_pair_t *kccwf_no_sync_race_pairs;
unsigned int kccwf_no_sync_race_pairs_num;

race_pair_t *kccwf_race_pairs_has_checked;
unsigned int kccwf_race_pairs_has_checked_num;
raw_spinlock_t kccwf_race_pairs_has_checked_lock;
/* global variable */

/* static global variable */
static atomic_t may_race_pair_trigger_flag = ATOMIC_INIT(0);
static atomic_t validate_race_pair_trigger_flag = ATOMIC_INIT(0);
static atomic_long_t read_watchpoints[REAL_NUM_WATCHPOINTS];
static atomic_long_t write_watchpoints[REAL_NUM_WATCHPOINTS];
// This lock is to ensure the correct access order of write
static raw_spinlock_t kccwf_write_access_buffer_lock;
static unsigned long kccwf_write_access_buffer_lockflags;
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

	kccwf_write_access_buffer = vzalloc(sizeof(write_access_info_t) * KCCWF_MAX_WRITE_ACCESS_INFOS);
	if (!kccwf_write_access_buffer){
		printk(KERN_ERR "Failed to allocate memory for kccwf_write_access_buffer\n");
		goto fail_exit;
    }
	raw_spin_lock_init(&kccwf_write_access_buffer_lock);

	kccwf_may_race_pairs = vzalloc(sizeof(race_pair_t) * KCCWF_MAX_RACE_PAIRS);
	if (!kccwf_may_race_pairs){
		printk(KERN_ERR "Failed to allocate memory for kccwf_may_race_pairs\n");
		goto fail_exit;
    }

	kccwf_no_sync_race_pairs = vzalloc(sizeof(race_pair_t) * KCCWF_NO_SYNC_RACE_PAIRS);
	if (!kccwf_no_sync_race_pairs){
		printk(KERN_ERR "Failed to allocate memory for kccwf_no_sync_race_pairs\n");
		goto fail_exit;
    }

	
	kccwf_race_pairs_has_checked = vzalloc(sizeof(race_pair_t) * KCCWF_RACE_PAIRS_HAS_CHECKED);
	if (!kccwf_race_pairs_has_checked){
		printk(KERN_ERR "Failed to allocate memory for kccwf_race_pairs_has_checked\n");
		goto fail_exit;
    }
	raw_spin_lock_init(&kccwf_race_pairs_has_checked_lock);

    current->kccwf_disable_count--;
    return 0;
fail_exit:
	current->kccwf_disable_count--;
	return -ENOMEM;

}

inline void kccwf_core_exit(void){
	current->kccwf_disable_count++;
	vfree(kccwf_read_access_infos_sn);
	vfree(kccwf_write_access_buffer);
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
	if (current->kccwf_disable_count || !addr || kccwf_mode == KCCWF_DISABLE_MODE) {
		goto exit_label;
	}
	if (is_stack_pointer((unsigned long)addr)) {
		if (KCCWF_DEBUG) atomic_long_inc(&stack_count);
		goto exit_label;
	}else {
		if (KCCWF_DEBUG) atomic_long_inc(&heap_count);
	}
	if(TIME_MEASUREMENT){
		end = ktime_get();
		delta = ktime_to_ns(ktime_sub(end, start));
		atomic_long_add(delta, &time_condition_check_total);
		atomic_long_inc(&count_condition_check);
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
		atomic_long_add(delta, &time_preparing_stage);
		atomic_long_inc(&count_preparing_stage);
	}
	if(kccwf_mode == KCCWF_MONITOR_MODE){
		if(get_random_u32_below(100) < DELAY_PROBABILITY){
            delay_time = get_random_u32_below(80);
        }else{
            delay_time = 0;
        }
		goto monitor;
	}
	// log part
	if (!is_write){
		if (KCCWF_DEBUG) atomic_long_inc(&kccwf_read_count);
		read_access_info_t read_access_info = { 
			.var_name = var_name,
			.var_addr = addr,
			.access_time = access_time,
			.tid = tid,
			.size = size,
			.sn = sn
		};
		log_read_access(&read_access_info);
	}else {
		if (KCCWF_DEBUG) atomic_long_inc(&kccwf_write_count);
		raw_spin_lock_irqsave(&kccwf_write_access_buffer_lock, kccwf_write_access_buffer_lockflags);
		// Ensure that the waiting queue is fully populated when running
		unsigned int _tail = (kccwf_write_access_buffer_tail + 1); 
		kccwf_write_access_buffer[_tail % KCCWF_MAX_WRITE_ACCESS_INFOS].access_time = ktime_get();
		kccwf_write_access_buffer[_tail % KCCWF_MAX_WRITE_ACCESS_INFOS].tid = tid;
		kccwf_write_access_buffer[_tail % KCCWF_MAX_WRITE_ACCESS_INFOS].var_addr = addr;
		kccwf_write_access_buffer[_tail % KCCWF_MAX_WRITE_ACCESS_INFOS].size = size;
		smp_mb();
		kccwf_write_access_buffer_tail = _tail;
		// printk(KERN_INFO "kccwf write,tail is %u\n",kccwf_write_access_buffer_tail);
		raw_spin_unlock_irqrestore(&kccwf_write_access_buffer_lock, kccwf_write_access_buffer_lockflags);
		wake_up(&kccwf_access_twbuffer.wq);
	}
	if (kccwf_mode == KCCWF_LOG_MODE){
		goto exit_label;
	}else if(kccwf_mode == KCCWF_CHECK_MODE){
		for (int i = 0;i < kccwf_race_pairs_has_checked_num;i++){
			if (var_name == kccwf_race_pairs_has_checked[i].read_name){
				if (sn == kccwf_race_pairs_has_checked[i].sn){
					printk(KERN_INFO "The read_name %lu in sn %lu has checked\n",var_name,sn);
					goto exit_label;
				}
			}
		}
		// pr_info("The kccwf_may_race_pairs num is %d\n",kccwf_may_race_pairs_num);
		for (int i = 0;i < kccwf_may_race_pairs_num;i++){
			if (var_name == kccwf_may_race_pairs[i].read_name){
				if (sn == kccwf_may_race_pairs[i].sn){
					delay_time = 2*kccwf_may_race_pairs[i].interval_time;
				}
			}
		}
	}else if(kccwf_mode == KCCWF_VALIDATE_MODE){
		// pr_info("The kccwf_may_race_pairs num is %d\n",kccwf_may_race_pairs_num);
		for (int i = 0;i < kccwf_race_pairs_has_checked_num;i++){
			if (var_name == kccwf_race_pairs_has_checked[i].read_name){
				if (sn == kccwf_race_pairs_has_checked[i].sn){
					printk(KERN_INFO "The read_name %lu in sn %lu has validated\n",var_name,sn);
					goto exit_label;
				}
			}
		}
		for (int i = 0;i < kccwf_no_sync_race_pairs_num;i++){
			if (var_name == kccwf_no_sync_race_pairs[i].read_name){
				if (sn == kccwf_no_sync_race_pairs[i].sn){
					unsigned long flags = 0;
					raw_spin_lock_irqsave(&kccwf_race_pairs_has_checked_lock, flags);
					delay_time = 10*kccwf_no_sync_race_pairs[i].interval_time;
					kccwf_race_pairs_has_checked[kccwf_race_pairs_has_checked_num].read_name = var_name;
					kccwf_race_pairs_has_checked[kccwf_race_pairs_has_checked_num].sn = sn;
					smp_mb();
					kccwf_race_pairs_has_checked_num++;
					printk(KERN_INFO "Validate read_name %lu in sn %ln\n",var_name,sn);
					raw_spin_unlock_irqrestore(&kccwf_race_pairs_has_checked_lock, flags);
				}
			}
		}
	}
	if (delay_time == 0){
		goto exit_label;
	}
monitor:
	// watch point part
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
EXPORT_SYMBOL(kccwf_rec_mem_access);

void enable_kccwf_free_rec(void){
	current->kccwf_free_enable_count++;
}
EXPORT_SYMBOL(enable_kccwf_free_rec);

void disable_kccwf_free_rec(void){
	current->kccwf_free_enable_count--;
}
EXPORT_SYMBOL(disable_kccwf_free_rec);