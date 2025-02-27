#ifndef CALL_STACK_H
#define CALL_STACK_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include "utils.h"

typedef struct func_call {
    unsigned long func_name;
    int func_line;
    __u64 func_call_stack_hash;

    struct list_head list;
} func_call_t;

typedef struct thread_chain {
    int tid;
    __u64 thread_call_stack_hash;

    struct list_head func_calls;
    struct list_head list;
} thread_chain_t;

extern struct list_head global_thread_chain_head;
extern spinlock_t thread_chain_lock;
extern unsigned long thread_chain_lock_flags; 

#define FNV_OFFSET_BASIS 0xcbf29ce484222325ULL
#define FNV_PRIME 0x100000001b3ULL
__u64 FNV1a_Hash_Ulong(unsigned long value); 

#endif // CALL_STACK_H