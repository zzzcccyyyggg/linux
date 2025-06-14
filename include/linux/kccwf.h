#ifndef CONFIG_KCCWF
#define CONFIG_KCCWF

#include "linux/journal-head.h"
#include "linux/tick.h"
#include <linux/atomic.h>
#include <linux/types.h>
#define MAX_LOG_ENTRIES 6553600 // 维持原条目数
#define KCCWF_DEBUG 0
#define TIME_MEASUREMENT 0

#define KCCWF_DISABLE_MODE      0x00000000
#define KCCWF_MONITOR_MODE      0x00000004
#define KCCWF_LOG_MODE      0x1
#define KCCWF_CHECK_MODE      0x2
#define KCCWF_VALIDATE_MODE      0x3

#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/kallsyms.h>

void kccwf_disable(void);
void kccwf_enable(void);

/* core.c */
void kccwf_rec_mem_access(const volatile void *addr, unsigned long var_name, int is_write, int file_line, int type);

#define KCCWF_MAX_VALIDAE_TIMES 0X1000

#define KCCWF_MAX_TESTING_TID_NUM 0X2
typedef struct {
    tid_t tids[KCCWF_MAX_TESTING_TID_NUM];
    int num;
} kccwf_testing_tids_t;

typedef struct {
    int mode;
    kccwf_testing_tids_t testing_tids;
    uint64_t bbs_state[KCCWF_MAX_TESTING_TID_NUM];
} kccwf_current_t;

extern kccwf_current_t kccwf_current;


int kccwf_core_init(void);
void kccwf_core_exit(void);

// statistical variables
typedef struct kccwf_statistical_var
{
    atomic_long_t heap_count;
    atomic_long_t stack_count;

    atomic_long_t kccwf_read_count;
    atomic_long_t kccwf_write_count;

    atomic_long_t time_condition_check_total;
    atomic_long_t count_condition_check;
    atomic_long_t time_preparing_stage;
    atomic_long_t count_preparing_stage;
    atomic_long_t time_watchpoint_processing_total;
    atomic_long_t count_watchpoint_processing_total;
} kccwf_statistical_var_t;
extern kccwf_statistical_var_t kccwf_statistical_var;

/* core.c */

int kccwf_tracker_init(void);
/* func_call_monitor.c */
#define KCCWF_THREADS_MONITORED 0x100000
extern atomic_t kccwf_threads_monitored[KCCWF_THREADS_MONITORED];
inline int func_call_monitor_init(void);
inline void func_call_monitor_exit(void);
/* func_call_monitor.c */
typedef struct {
    unsigned long var_name_1;
    unsigned long var_name_2;
    unsigned long call_stack_hash_1;
    unsigned long call_stack_hash_2;
    bool is_synchronized;
} may_race_pair_t;

#define MAX_RACE_PAIR_NUM 1024
typedef struct may_race_pair_list {
    uint32_t num;
    may_race_pair_t pairs[MAX_RACE_PAIR_NUM];
} may_race_pair_list_t;
extern may_race_pair_list_t g_may_race_pair_list;

#endif