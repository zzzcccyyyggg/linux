#include "wp_checker.h"
#include "report.h"
static __always_inline atomic_long_t *
insert_watchpoint(atomic_long_t *watchpoints, unsigned long addr)
{
	atomic_long_t *watchpoint;
	long expect_val = INVALID_VALUE;
	const int slot = watchpoint_slot(addr);
	for (int i = 0; i < NUM_SLOTS; i++) {
		expect_val = INVALID_VALUE;
		watchpoint = &watchpoints[SLOT_IDX(slot, i)];

		if (atomic_long_try_cmpxchg(watchpoint, &expect_val,
					    PROCESS_VALUE)) {
			return watchpoint;
		}
	}
	return NULL;
}

static __always_inline void remove_watchpoint(atomic_long_t *watchpoint)
{
	if (KCCWF_DEBUG) {
		unsigned long addr_masked;
		size_t size;
		long encoded_wp = atomic_long_read(watchpoint);
		decode_watchpoint(encoded_wp, &addr_masked, &size);
		printk(KERN_INFO "remove read: var_addr %lx int tid %d\n",
		       addr_masked, current->pid);
	}
	atomic_long_set(watchpoint, INVALID_VALUE);
}

static __always_inline atomic_long_t *
find_watchpoint(atomic_long_t *watchpoints, access_info_t *var_access_info)
{
	atomic_long_t *watchpoint;
	const unsigned long addr_masked =
		(unsigned long)(var_access_info->var_addr) &
		WATCHPOINT_ADDR_MASK;
	long found_watchpoint;
	unsigned long watchpoint_addr_masked;
	size_t size;
	const int slot =
		watchpoint_slot((unsigned long)var_access_info->var_addr);
	for (int i = 0; i < NUM_SLOTS; i++) {
		watchpoint = &watchpoints[SLOT_IDX_FAST(slot, i)];
		found_watchpoint = atomic_long_read(watchpoint);
		decode_watchpoint(found_watchpoint, &watchpoint_addr_masked,
				  &size);
		if (matching_access(watchpoint_addr_masked,
				    var_access_info->size, addr_masked, size)) {
			if (atomic_long_try_cmpxchg(watchpoint,
						    &found_watchpoint,
						    CONSUMED_VALUE)) {
				printk(KERN_INFO
				       "var addr %lx, addr masked %lx\n",
				       (unsigned long)var_access_info->var_addr,
				       addr_masked);
				return watchpoint;
			}
		}
	}
	return NULL;
}

static __always_inline void found_watchpoint(atomic_long_t *watchpoints,
					     report_info_t *report_infos,
					     reported_info_t *reported_info,
					     access_info_t *var_access_info,
					     atomic_long_t *watchpoint)
{
	report_race(report_infos, reported_info, var_access_info->var_addr,
		    var_access_info->is_write, watchpoint - watchpoints,
		    var_access_info->var_name, var_access_info->file_line,
		    "DATARACE");
	printk(KERN_INFO "Found watch_point %d\n", watchpoint - watchpoints);
	long expect_val = CONSUMED_VALUE;
	atomic_long_try_cmpxchg(watchpoint, &expect_val, REPORTED_VALUE);
}

static __always_inline void setup_watchpoint(atomic_long_t *watchpoints,
					     report_info_t *report_infos,
					     raw_spinlock_t *report_lock,
					     access_info_t *var_access_info)
{
	u64 old, new, diff;
	atomic_long_t *watchpoint;
	long expect_val = PROCESS_VALUE;

	watchpoint = insert_watchpoint(
		watchpoints, (unsigned long)var_access_info->var_addr);
	if (!watchpoint) {
		printk(KERN_INFO "No watchpoint available\n");
		return;
	}

	int cpu = raw_smp_processor_id();
	int tid = current->pid;
	set_report_info(report_infos, report_lock, var_access_info->var_addr,
			var_access_info->is_write, watchpoint - watchpoints,
			var_access_info->file_line, var_access_info->var_name,
			tid, cpu);
	long enconded_watchpoint =
		encode_watchpoint((unsigned long)var_access_info->var_addr,
				  var_access_info->size);
	if (!atomic_long_try_cmpxchg_relaxed(watchpoint, &expect_val,
					     enconded_watchpoint)) {
		clear_report_info(report_infos, watchpoint - watchpoints);
		remove_watchpoint(watchpoint);
		return;
	}

	int delay_time = var_access_info->delay_time;
	while (delay_time >= 2000) {
		udelay(2000);
		delay_time -= 2000;
	}
	udelay(delay_time);
	unsigned long temp = (unsigned long)var_access_info->var_addr;
	if (atomic_long_try_cmpxchg_relaxed(watchpoint, &enconded_watchpoint,
					    CONSUMED_VALUE)) {
		clear_report_info(report_infos, watchpoint - watchpoints);
		remove_watchpoint(watchpoint);
		return;
	} else {
		while (atomic_long_read(watchpoint) == REPORTED_VALUE) {
			udelay(10);
			clear_report_info(report_infos,
					  watchpoint - watchpoints);
			remove_watchpoint(watchpoint);
			return;
		}
	}
}

inline void watchpoints_monitor(
	access_info_t *var_access_info, atomic_long_t *read_watchpoints,
	atomic_long_t *write_watchpoints, report_info_t *read_report_infos,
	raw_spinlock_t *read_report_lock, report_info_t *write_report_infos,
	raw_spinlock_t *write_report_lock, reported_info_t *reported_info)
{
	atomic_long_t *watchpoint;
	if (var_access_info->is_write) {
		watchpoint =
			find_watchpoint(write_watchpoints, var_access_info);
		if (watchpoint) {
			found_watchpoint(write_watchpoints, write_report_infos,
					 reported_info, var_access_info,
					 watchpoint);
		} else {
			watchpoint = find_watchpoint(read_watchpoints,
						     var_access_info);
			if (watchpoint) {
				found_watchpoint(read_watchpoints,
						 read_report_infos,
						 reported_info, var_access_info,
						 watchpoint);
			} else {
				setup_watchpoint(write_watchpoints,
						 write_report_infos,
						 write_report_lock,
						 var_access_info);
			}
		}
	} else {
		// printk(KERN_INFO "kccwf_rec_mem_access: read var_addr %lx int tid %d\n",(unsigned long)addr,tid);
		watchpoint =
			find_watchpoint(write_watchpoints, var_access_info);
		if (watchpoint) {
			found_watchpoint(write_watchpoints, write_report_infos,
					 reported_info, var_access_info,
					 watchpoint);
		} else {
			setup_watchpoint(read_watchpoints, read_report_infos,
					 read_report_lock, var_access_info);
		}
	}
}