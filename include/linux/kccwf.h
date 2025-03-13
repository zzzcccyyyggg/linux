#ifndef CONFIG_KCCWF
#define CONFIG_KCCWF
#include <linux/types.h>
#define MAX_LOG_ENTRIES 6553600 // 维持原条目数
#define KCCWF_DEBUG 0

#define KCCWF_MONITOR_ENABLE    BIT(0)  // 0x00000001
#define KCCWF_LOG_ENABLE        BIT(1)  // 0x00000002
#define KCCWF_RANDOM_ENABLE     BIT(2)  // 0x00000004
#define KCCWF_VALIDATE_ENABLE   BIT(4)  
/* 模式组合定义 (mode presets) */
#define KCCWF_DISABLE_MODE      0x00000000
#define KCCWF_MONITOR_MODE      KCCWF_MONITOR_ENABLE
#define KCCWF_STABLE_SAMPLING  (KCCWF_MONITOR_ENABLE | KCCWF_LOG_ENABLE)
#define KCCWF_RANDOM_SAMPLING  (KCCWF_MONITOR_ENABLE | KCCWF_RANDOM_ENABLE | KCCWF_LOG_ENABLE)
#define KCCWF_VALIDATE_MODE    (KCCWF_MONITOR_ENABLE | KCCWF_RANDOM_ENABLE | KCCWF_VALIDATE_ENABLE)

/* 功能检测宏 (feature check macros) */
#define IS_MONITOR_ENABLED(mode)    ((mode) & KCCWF_MONITOR_ENABLE)
#define IS_LOG_ENABLED(mode)        ((mode) & KCCWF_LOG_ENABLE)
#define IS_RANDOM_ENABLED(mode)     ((mode) & KCCWF_RANDOM_ENABLE)

#define TURN_OFF_LOG(mode)        ((mode) &= ~KCCWF_LOG_ENABLE)
#define TURN_OFF_MONITOR(mode)    ((mode) &= ~KCCWF_MONITOR_ENABLE)
#define TURN_OFF_RANDOM(mode)     ((mode) &= ~KCCWF_RANDOM_ENABLE)

typedef struct delay_var
{
    unsigned long var_name;
    unsigned long call_stack_hash;
    int delay_time;
} delay_var_t;

extern delay_var_t global_sync_delay[2];
extern delay_var_t global_validate_delay[256];

extern int stable_logging_phase;
extern int random_delay_logging_phase;
extern int checking_sync_phase;
extern int validating_phase;
extern int kccwf_mode;

void rec_mem_access(const volatile void *addr, unsigned long var_name, int is_write, int file_line, int type);


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



// 日志条目结构体（优化对齐）
typedef struct __attribute__((aligned(64))) access_info {
    /* static info */
    int is_write;
    int file_line;
    pid_t tid;
    int type;
    int delay_time;
    int is_skip;
    unsigned long var_name;
    /* dynamic info */
    const volatile void *var_addr;
    unsigned long call_stack_hash;
    unsigned long access_time;
    /* control info */
} access_info_t;

#define LOG_FILE "/var/log/mem_access.log"
extern access_info_t **log_buffer;
extern DEFINE_PER_CPU(int, kccwf_log_index);
extern DEFINE_PER_CPU(int, head);
extern DEFINE_PER_CPU(int, tail);
extern atomic_t overflow_count;

// 文件操作相关
extern struct file *log_file;

extern struct task_struct *bg_thread;
extern bool kccwf_log_file_clean;
extern int is_log_init;
int flush_logs(void *arg);
void log_access_info(const access_info_t *var_access_info);
void logger_init(void);
void logger_exit(void);
void clean_log(void);


extern atomic_long_t heap_count;
extern atomic_long_t stack_count;

extern atomic_long_t kccwf_read_count;
extern atomic_long_t kccwf_write_count;

// 时间统计信息
// 定义统计变量
extern atomic_long_t time_condition_check_total;
extern atomic_long_t time_stack_heap_total;
extern atomic_long_t time_rw_counters_total;
extern atomic_long_t time_get_time_tid_total;
extern atomic_long_t time_delay_calculation_total;
extern atomic_long_t time_access_info_setup_total;
extern atomic_long_t time_watchpoint_processing_total;

extern atomic_long_t count_condition_check;
extern atomic_long_t count_stack_heap;
extern atomic_long_t count_rw_counters;
extern atomic_long_t count_get_time_tid;
extern atomic_long_t count_delay_calculation;
extern atomic_long_t count_access_info_setup;
extern atomic_long_t count_watchpoint_processing;

// BUCKET 
#define KCCWF_NUM_WATCHPOINTS 8192
#define KCCWF_CHECK_ADJACENT 3
#define NUM_SLOTS (1 + 2*KCCWF_CHECK_ADJACENT)
#define SLOT_IDX(slot, i) (slot + ((i + KCCWF_CHECK_ADJACENT) % NUM_SLOTS))
#define SLOT_IDX_FAST(slot, i) (slot + i)
#define REAL_NUM_WATCHPOINTS (KCCWF_NUM_WATCHPOINTS + NUM_SLOTS - 1)

// FIX ME REPLACE WITH A FAST HASH FUNCTION
static __always_inline int watchpoint_slot(unsigned long addr) {
    const unsigned long A = 2654435761U; // 黄金比例素数 (2^32 / φ)
    return (addr * A) % KCCWF_NUM_WATCHPOINTS;
}

#endif