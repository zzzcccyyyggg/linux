#ifndef KCCWF_REPORT_H
#define KCCWF_REPORT_H

#include "encoding.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stacktrace.h>
#include <asm/unwind.h>
#include <linux/kccwf.h>
#define NUM_STACK_ENTRIES 0x40
#define MAX_REPORTED_NUM 0X100
typedef struct report_info {
	unsigned long stack_entries[NUM_STACK_ENTRIES];
	int num_entries;
	struct task_struct *task;
	unsigned long hash;
	unsigned long var_name;
	int file_line;
	int tid;
	int cpu;
} report_info_t;

void set_report_info(report_info_t *report_infos, raw_spinlock_t *report_lock,
		     const volatile void *addr, int is_write,
		     int watchpoint_idx, int file_line, unsigned long var_name,
		     int tid, int cpu);

void clear_report_info(report_info_t *report_infos, int watchpoint_idx);

typedef struct reported_pairs {
	unsigned long name_1;
	unsigned long name_2;
} reported_pairs_t;

typedef struct reported_info {
	reported_pairs_t reported_pairs[REAL_NUM_WATCHPOINTS];
	raw_spinlock_t lock;
	unsigned long flags;
	int count;
} reported_info_t;
void report_race(report_info_t *report_infos, reported_info_t *report_info,
		 const volatile void *addr, int is_write, int watchpoint_idx,
		 unsigned long var_name, int file_line, char *report_type);

void push_reported(reported_info_t *report_info, unsigned long name_1,
		   unsigned long name_2);
bool check_reported(reported_info_t *report_info, unsigned long name_1,
		    unsigned long name_2);

void kccwf_report_init(unsigned long *recorded_pair, int num,
		       reported_info_t *reported_info);
#endif // REPORT_H