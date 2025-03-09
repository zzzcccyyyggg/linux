#define CONFIG_KCCWF
#ifdef CONFIG_KCCWF
#include <linux/types.h>
#define MAX_LOG_ENTRIES 6553600 // 维持原条目数


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
#endif