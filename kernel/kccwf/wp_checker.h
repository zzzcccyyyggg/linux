#ifndef KCCWF_WP_CHECKER_H
#define KCCWF_WP_CHECKER_H

#include "linux/kccwf.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/ktime.h>
#include <linux/delay.h>
#include <linux/kccwf.h>
#include <linux/slab.h>
#include <linux/mm.h>

#include "encoding.h"
#include "report.h"
#include "race_pairs.h"

#define INVALID_VALUE 0
#define CONSUMED_VALUE 1
#define PROCESS_VALUE 2
#define REPORTED_VALUE 3

#define DELAY_PROBABILITY 71

typedef struct __attribute__((aligned(64))) access_info {
	/* static info */
	int is_write;
	int file_line;
	pid_t tid;
	int size;
	int delay_time;
	int is_skip;
	unsigned long var_name;
	const volatile void *var_addr;
	unsigned long call_stack_hash;
	unsigned long access_time;
	int sn;
} access_info_t;

inline void watchpoints_monitor(
	access_info_t *var_access_info, atomic_long_t *read_watchpoints,
	atomic_long_t *write_watchpoints, report_info_t *read_report_infos,
	raw_spinlock_t *read_report_lock, report_info_t *write_report_infos,
	raw_spinlock_t *write_report_lock, reported_info_t *reported_info);

#endif // CORE_H