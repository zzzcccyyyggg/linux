#ifndef CONFIG_KCCWF
#define CONFIG_KCCWF
#include "linux/spinlock_types.h"
#include <linux/atomic.h>
#include <linux/types.h>
#define MAX_LOG_ENTRIES 6553600 // 维持原条目数
#define KCCWF_DEBUG 0
#define TIME_MEASUREMENT 0

#define KCCWF_DISABLE_MODE      0x00000000
#define KCCWF_MONITOR_MODE      0x00000000
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


/* core.c */
void kccwf_rec_mem_access(const volatile void *addr, unsigned long var_name, int is_write, int file_line, int type);
// The maximum number of verifications per test
#define KCCWF_MAX_VALIDAE_TIMES 0X1
typedef struct {
    atomic_t kccwf_validate_times;
    int kccwf_mode; 
} kccwf_current_t;
extern kccwf_current_t kccwf_current;


typedef struct __attribute__((aligned(64))) access_info {
    /* static info */
    int is_write;
    int file_line;
    pid_t tid;
    int size;
    int delay_time;
    int is_skip;
    unsigned long var_name;
    /* dynamic info */
    const volatile void *var_addr;
    unsigned long call_stack_hash;
    unsigned long access_time;
    /* control info */
} access_info_t;

#define KCCWF_MAX_READ_ACCESS_INFOS 512000
#define KCCWF_MAX_WRITE_ACCESS_INFOS 51200
#define KCCWF_MAX_RACE_PAIRS 0X10000
#define KCCWF_NO_SYNC_RACE_PAIRS 0X1000
#define KCCWF_RACE_PAIRS_HAS_CHECKED 0X10000
typedef struct __attribute__((aligned(64))) read_access_info {
    pid_t tid;
    unsigned long var_name;
    const volatile void *var_addr;
    unsigned long access_time;
    unsigned long sn; // Serial Number
    unsigned int size;
    int file_line;
} read_access_info_t;

typedef struct __attribute__((aligned(64))) write_access_info {
    pid_t tid;
    const volatile void *var_addr;
    unsigned long access_time;
    unsigned int size;
} write_access_info_t;

typedef struct {
    write_access_info_t *kccwf_write_access_buffer;
    unsigned int kccwf_write_access_buffer_head;
    unsigned int kccwf_write_access_buffer_tail;
    raw_spinlock_t kccwf_write_access_buffer_lock;
    unsigned long kccwf_write_access_buffer_lockflags;
} kccwf_write_access_buffer_t;
extern kccwf_write_access_buffer_t kccwf_write_access_buffer;

extern atomic64_t *kccwf_read_access_infos_sn;



typedef struct __attribute__((aligned(64))) race_pair {
    unsigned long read_name;
    unsigned long sn;
    unsigned long interval_time;
    struct race_pair *next;
} race_pair_t;

typedef struct race_pair_entry {
    race_pair_t race_pair;
    struct list_head list;
}race_pair_entry_t;

typedef struct {
    struct list_head may_race_list;
    struct list_head no_sync_race_list;
    struct list_head checked_race_list;
    
    spinlock_t may_race_lock;
    spinlock_t no_sync_race_lock;
    spinlock_t checked_race_lock;
} kccwf_concurrent_pairs_t;

void kccwf_concurrent_pairs_init(kccwf_concurrent_pairs_t *pairs);
void kccwf_add_may_race_pair(kccwf_concurrent_pairs_t *pairs, race_pair_t *pair);
void kccwf_add_checked_race_pair(kccwf_concurrent_pairs_t *pairs, race_pair_t *pair);
struct race_pair_entry *kccwf_find_race_pair(
    struct list_head *head, 
    spinlock_t *lock,
    const race_pair_t *target,
    bool (*cmp)(const race_pair_t *, const race_pair_t *));
void kccwf_remove_race_pair(
    kccwf_concurrent_pairs_t *pairs, 
    const race_pair_t *pair,
    bool (*cmp)(const race_pair_t *, const race_pair_t *));
bool kccwf_race_pair_cmp(const race_pair_t *a, const race_pair_t *b);
bool kccwf_race_pair_cmp_by_varname(const race_pair_t *a, const race_pair_t *b);
extern kccwf_concurrent_pairs_t kccwf_concurrent_pairs;


int kccwf_core_init(void);
void kccwf_core_exit(void);
/* core.c */


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

// statistical variables

/* core.c */

/* timewindow_buffer.c */
#define KCCWF_TIME_WINDOW   100000   // Time window threshold (nanoseconds)
#define KCCWF_RING_BUFFER_SIZE    0x51200      // Ring buffer size
typedef struct {
    read_access_info_t records[KCCWF_RING_BUFFER_SIZE];
    atomic_long_t head;
    atomic_long_t tail;
    
    wait_queue_head_t wq;
    spinlock_t lock;
    spinlock_t read_acccess_lock;
    struct task_struct *handler_thread;
    bool thread_running;
} TimeWindowBuffer;

extern TimeWindowBuffer kccwf_access_twbuffer;

int kccwf_access_twbuffer_init(void);
void kccwf_access_twbuffer_clean(void);
void log_read_access(read_access_info_t* read_access);

/* timewindow_buffer.c */

/* encoding.c */
#define KCCWF_NUM_WATCHPOINTS 8192
#define KCCWF_CHECK_ADJACENT 3
#define NUM_SLOTS (1 + 2*KCCWF_CHECK_ADJACENT)
#define SLOT_IDX(slot, i) (slot + ((i + KCCWF_CHECK_ADJACENT) % NUM_SLOTS))
#define SLOT_IDX_FAST(slot, i) (slot + i)
#define REAL_NUM_WATCHPOINTS (KCCWF_NUM_WATCHPOINTS + NUM_SLOTS - 1)

// [FIX ME] replace with a hash function that can be more efficient and able to avoid hash collisions
static __always_inline int watchpoint_slot(unsigned long addr) {
    const unsigned long A = 2654435761U; // 黄金比例素数 (2^32 / φ)
    return (addr * A) % KCCWF_NUM_WATCHPOINTS;
}
/* encoding.c */

/* func_call_monitor.c */
#define KCCWF_THREADS_MONITORED 0x100000
extern atomic_t kccwf_threads_monitored[KCCWF_THREADS_MONITORED];
inline int func_call_monitor_init(void);
inline void func_call_monitor_exit(void);
/* func_call_monitor.c */

#endif