#ifndef KCCWF_EXEC_FLOW
#define KCCWF_EXEC_FLOW

#include <linux/kccwf.h>
#include <linux/list.h>  // 确保包含链表头文件

struct block_event {
    u64 timestamp;
    u64 block_id;
    struct list_head list;
};

struct ccwf_exec_bbflow_list {
    struct list_head head;
    spinlock_t lock;
    struct kmem_cache *cache;
};

extern struct ccwf_exec_bbflow_list ccwf_event_list;  // 声明全局变量

#endif /* KCCWF_EXEC_FLOW */