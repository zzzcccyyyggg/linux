#ifndef KCCWF_CORE_H
#define KCCWF_CORE_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/ktime.h>
#include <linux/delay.h>
#include <linux/kccwf.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include "call_stack.h"
#include "encoding.h"
#include "report.h"

#define INVALID_VALUE 0
#define CONSUMED_VALUE 1
#define PROCESS_VALUE 2

#define VALUE_CHANGED_FALSE 0
#define VALUE_CHANGED_TRUE 1

#define DELAY_PROBABILITY 5

extern int stable_logging_phase;
extern int random_delay_logging_phase;
extern int checking_sync_phase;
extern int validating_phase;
extern int checker_start;

// 函数定义
#define PTR_TO_LONG(ptr) ((long)(unsigned long)(ptr))
// FIX ME: USE MATCHING access
#define DEFINE_FIND_WATCHPOINT_FUNCTION(name, watchpoints_array)                  \
	static __always_inline atomic_long_t *name(                               \
		access_info_t *var_access_info, long *found_addr)                 \
	{                                                                         \
		atomic_long_t *watchpoint;                                        \
		const unsigned long addr_masked =                                 \
			(unsigned long)(var_access_info->var_addr) &              \
			WATCHPOINT_ADDR_MASK;                                     \
		long found_watchpoint;                                            \
		unsigned long watchpoint_addr_masked;                             \
		size_t size;                                                      \
		const int slot = watchpoint_slot(                                 \
			(unsigned long)var_access_info->var_addr);                \
		for (int i = 0; i < NUM_SLOTS; i++) {                             \
			watchpoint =                                              \
				&watchpoints_array[SLOT_IDX_FAST(slot, i)];       \
			found_watchpoint = atomic_long_read(watchpoint);          \
			decode_watchpoint(found_watchpoint,                       \
					  &watchpoint_addr_masked, &size);        \
			if (matching_access(watchpoint_addr_masked,               \
					    var_access_info->type,                \
					    addr_masked, size)) {                 \
				if (atomic_long_try_cmpxchg(watchpoint,           \
							    &found_watchpoint,    \
							    CONSUMED_VALUE)) {    \
					*found_addr =                             \
						(unsigned long)var_access_info    \
							->var_addr;               \
					printk(KERN_INFO                          \
					       "var addr %lx, addr masked %lx\n", \
					       (unsigned long)var_access_info     \
						       ->var_addr,                \
					       addr_masked);                      \
					return watchpoint;                        \
				}                                                 \
			}                                                         \
		}                                                                 \
		return NULL;                                                      \
	}

#define DEFINE_INSERT_WATCHPOINT_FUNCTION(name, watchpoints_array)           \
	static __always_inline atomic_long_t *name(unsigned long addr)       \
	{                                                                    \
		atomic_long_t *watchpoint;                                   \
		long expect_val = INVALID_VALUE;                             \
		const int slot = watchpoint_slot(addr);                      \
		for (int i = 0; i < NUM_SLOTS; i++) {                        \
			expect_val = INVALID_VALUE;                          \
			watchpoint = &watchpoints_array[SLOT_IDX(slot, i)];  \
                                                                             \
			if (atomic_long_try_cmpxchg(watchpoint, &expect_val, \
						    PROCESS_VALUE)) {        \
				return watchpoint;                           \
			}                                                    \
		}                                                            \
		return NULL;                                                 \
	}

#define DEFINE_READ_INSTRUMENTED_MEMORY(bits)                          \
	static __always_inline u##bits read_instrumented_memory##bits( \
		const volatile void *addr)                             \
	{                                                              \
		return *(volatile u##bits *)(uintptr_t)addr;           \
	}

#define DEFINE_SETUP_WATCHPOINT_FUNCTION(name, watchpoints_array)              \
	static __always_inline void setup_##name##_watchpoint(                 \
		access_info_t *var_access_info)                                \
	{                                                                      \
		u64 old, new, diff;                                            \
		atomic_long_t *watchpoint;                                     \
		int value_change = VALUE_CHANGED_FALSE;                        \
		long expect_val = PROCESS_VALUE;                               \
                                                                               \
		watchpoint = insert_##name##_watchpoint(                       \
			(unsigned long)var_access_info->var_addr);             \
		if (!watchpoint) {                                             \
			printk(KERN_INFO "No watchpoint available\n");         \
			return;                                                \
		}                                                              \
                                                                               \
		int cpu = raw_smp_processor_id();                              \
		int tid = current->pid;                                        \
		set_##name##_report_info(var_access_info->var_addr,            \
					 var_access_info->is_write,            \
					 watchpoint - watchpoints_array,       \
					 var_access_info->file_line,           \
					 var_access_info->var_name, tid, cpu); \
		long enconded_watchpoint = encode_watchpoint(                  \
			(unsigned long)var_access_info->var_addr,              \
			var_access_info->type);                                \
		if (!atomic_long_try_cmpxchg_relaxed(watchpoint, &expect_val,  \
						     enconded_watchpoint)) {   \
			clear_##name##_report_info(watchpoint -                \
						   watchpoints_array);         \
			remove_watchpoint(watchpoint);                         \
			return;                                                \
		}                                                              \
                                                                               \
		int delay_time = var_access_info->delay_time;                  \
		while (delay_time >= 2000) {                                   \
			udelay(2000);                                          \
			delay_time -= 2000;                                    \
		}                                                              \
		udelay(delay_time);                                            \
		unsigned long temp = (unsigned long)var_access_info->var_addr; \
		if (atomic_long_try_cmpxchg_relaxed(watchpoint,                \
						    &enconded_watchpoint,      \
						    CONSUMED_VALUE)) {         \
			clear_##name##_report_info(watchpoint -                \
						   watchpoints_array);         \
			remove_watchpoint(watchpoint);                         \
		}                                                              \
	}

#define DEFINE_FOUND_WATCHPOINT_FUNCTION(name, watchpoints_array)           \
	static __always_inline void found_##name##_watchpoint(              \
		access_info_t *var_access_info, atomic_long_t *watchpoint,  \
		long found_addr)                                            \
	{                                                                   \
		name##_report_race(var_access_info->var_addr,               \
				   var_access_info->is_write,               \
				   watchpoint - watchpoints_array,          \
				   var_access_info->var_name,               \
				   var_access_info->file_line);             \
		printk(KERN_INFO "Found watch_point %d\n",                  \
		       watchpoint - watchpoints_array);                     \
		clear_##name##_report_info(watchpoint - watchpoints_array); \
		remove_watchpoint(watchpoint);                              \
	}

#endif // CORE_H