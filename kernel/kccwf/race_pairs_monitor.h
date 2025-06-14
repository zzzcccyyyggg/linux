#ifndef _KCCWF_RACE_PAIRS_MONITOR_H
#define _KCCWF_RACE_PAIRS_MONITOR_H
#include "linux/types.h"
#include "ring_buffer.h"
#include "encoding.h"
#include "race_pairs.h"
#include "report.h"
#include "tracker.h"
#include <linux/kccwf.h>
#include <linux/xxhash.h>
#include <linux/wait.h>
#define KCCWF_TIME_WINDOW 10000000 // Time window threshold (nanoseconds)
#define KCCWF_RING_BUFFER_SIZE 0x51200 // Ring buffer size
typedef struct {
	ring_buffer_t read_rb;
	ring_buffer_t write_rb;
	wait_queue_head_t wq;
	struct task_struct *handler_thread;
	bool thread_running;
	atomic_t rp_thread_initialized;
	
} race_pairs_monitor_t;

int race_pairs_monitor_init(race_pairs_monitor_t *rp_monitor,concurrent_pairs_t *concurrent_pairs);
void race_pairs_monitor_clean(race_pairs_monitor_t *rp_monitor);
unsigned long log_read_access(race_pairs_monitor_t *rp_monitor, read_access_info_t *read_access);
void process_write_access(race_pairs_monitor_t *rp_monitor,write_access_info_t *write_access_info,concurrent_pairs_t *concurrent_pairs);

#endif