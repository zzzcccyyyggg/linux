#ifndef _KCCWF_TRACKER_H
#define _KCCWF_TRACKER_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/errno.h>

#define KCCWF_TRACKER_EFULL    (-ENOSPC)  // 跟踪条目已满
#define KCCWF_TRACKER_EINVAL   (-EINVAL)  // 无效参数
#define KCCWF_TRACKER_ENOMEM   (-ENOMEM)  // 内存不足

#define THREAD_HASH_BITS    8
#define VAR_HASH_BITS       8
#define STACK_HASH_BITS     8
#define MAX_STACK_ENTRIES_PER_SLOT 32

struct kccwf_thread_tracker;
struct kccwf_var_entry;
struct kccwf_stack_entry;

/* 哈希计算函数 */
unsigned long kccwf_calc_stack_hash(unsigned long *stack, int stack_size);

/* 线程跟踪器管理 */
struct kccwf_thread_tracker *kccwf_get_thread_tracker(pid_t pid);

int add_tracker(pid_t pid);
/* 访问计数接口 */
long kccwf_fetch_inc_access_by_stack(unsigned long var_name, unsigned long *stack, unsigned int stack_size);
int kccwf_fetch_inc_access_by_hash(unsigned long var_name, unsigned long stack_hash);
/* 初始化与清理 */
int kccwf_tracker_init(void);
void kccwf_tracker_exit(void);

#endif /* _KCCWF_TRACKER_H */