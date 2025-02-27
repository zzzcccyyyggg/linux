#ifndef CORE_H
#define CORE_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/ktime.h>
#include <linux/delay.h>
#include <linux/kccwf.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include "call_stack.h"
#include "report.h"

#define MAX_WATCHPOINTS 4096

#define INVALID_VALUE 0
#define CONSUMED_VALUE 1
#define PROCESS_VALUE 2

#define VALUE_CHANGED_FALSE 0
#define VALUE_CHANGED_TRUE 1

#define DELAY_PROBABILITY 20


extern delay_var_t global_sync_delay[2];
extern delay_var_t global_validate_delay[2];

extern int stable_logging_phase;
extern int random_delay_logging_phase;
extern int checking_sync_phase;
extern int validating_phase;
extern int checker_start;

// 函数定义
#define PTR_TO_LONG(ptr) ((long)(unsigned long)(ptr))

#define DEFINE_FIND_WATCHPOINT_FUNCTION(name, watchpoints_array)                                \
    static __always_inline atomic_long_t *name(access_info_t var_access_info, long *found_addr) \
    {                                                                                           \
        atomic_long_t *watchpoint;                                                              \
        for (int i = 0; i < MAX_WATCHPOINTS; i++)                                               \
        {                                                                                       \
            watchpoint = &watchpoints_array[i];                                                 \
            long temp = (long)(var_access_info.var_addr);                                     \
            long addr = atomic_long_read(watchpoint); \
            if(addr == temp){ \
                if(atomic_long_try_cmpxchg(watchpoint, &temp, CONSUMED_VALUE)  )           \
                {                                                                                   \
                    *found_addr = (long)var_access_info.var_addr;                                         \
                    printk(KERN_INFO "var addr %lu",(long)var_access_info.var_addr);\
                    return watchpoint;                                                              \
                }}                                                                                   \
        }                                                                                       \
        return NULL;                                                                            \
    }

#define DEFINE_INSERT_WATCHPOINT_FUNCTION(name, watchpoints_array)              \
    static inline atomic_long_t *name(unsigned long addr)         \
    {                                                                           \
        atomic_long_t *watchpoint;                                              \
        long expect_val = INVALID_VALUE; \
        for (int i = 0; i < MAX_WATCHPOINTS; i++)                               \
        {                                                                       \
            expect_val = INVALID_VALUE;                                    \
            watchpoint = &watchpoints_array[i];                                 \
                                                                                \
            if (atomic_long_try_cmpxchg(watchpoint, &expect_val, PROCESS_VALUE)) \
            {                                                                   \
                return watchpoint;                                              \
            }                                                                   \
        }                                                                       \
        return NULL;                                                            \
    }

#define DEFINE_READ_INSTRUMENTED_MEMORY(bits)                                \
    static u##bits read_instrumented_memory##bits(const volatile void *addr) \
    {                                                                        \
        return *(volatile u##bits *)(uintptr_t)addr;                         \
    }

#define DEFINE_SETUP_WATCHPOINT_FUNCTION(name, watchpoints_array)                                                    \
    static void setup_##name##_watchpoint(access_info_t var_access_info)                                             \
    {                                                                                                                \
        u64 old, new, diff;                                                                                          \
        atomic_long_t *watchpoint;                                                                                   \
        int value_change = VALUE_CHANGED_FALSE;                                                                      \
        long expect_val = PROCESS_VALUE;                                                                             \
                                                                                                                     \
        watchpoint = insert_##name##_watchpoint((unsigned long)var_access_info.var_addr);  \
        if (!watchpoint)                                                                                             \
        {                                                                                                            \
            printk(KERN_INFO "No watchpoint available\n");                                                           \
            return;                                                                                                  \
        }                                                                                                            \
                                                                                                                      \
        set_##name##_report_info(var_access_info.var_addr, var_access_info.is_write, watchpoint - watchpoints_array, \
                                 var_access_info.file_line,var_access_info.var_name);                                                         \
        if(!atomic_long_try_cmpxchg_relaxed(watchpoint, &expect_val, (unsigned long)var_access_info.var_addr)){         \
            clear_##name##_report_info(watchpoint - watchpoints_array);                                              \
            remove_watchpoint(watchpoint);                                                                           \
            return;\
        }\
                                                                                                                     \
        int delay_time = var_access_info.delay_time;                                                                 \
        while (delay_time >= 2000)                                                                                   \
        {                                                                                                            \
            udelay(2000);                                                                                            \
            delay_time -= 2000;                                                                                      \
        }                                                                                                            \
        udelay(delay_time);                                                                                          \
        unsigned long temp = (unsigned long)var_access_info.var_addr;        \
        if (atomic_long_try_cmpxchg_relaxed(watchpoint, &temp, CONSUMED_VALUE))                               \
        {                                                                                                            \
            if (var_access_info.var_name == 17713640239220804443UL){\
                printk(KERN_INFO "watchpoint number %d\n",(watchpoint-watchpoints_array));\
            }\
            clear_##name##_report_info(watchpoint - watchpoints_array);                                              \
            remove_watchpoint(watchpoint);                                                                           \
        }                                                                                                            \
}                                                                                                                    \

#define DEFINE_FOUND_WATCHPOINT_FUNCTION(name, watchpoints_array)                                                    \
    static void found_##name##_watchpoint(access_info_t var_access_info, atomic_long_t *watchpoint, long found_addr) \
    {                                                                                                                \
            name##_report_race(var_access_info.var_addr, var_access_info.is_write,                                   \
                                watchpoint - watchpoints_array, var_access_info.var_name,                             \
                                var_access_info.file_line);                                                           \
            printk(KERN_INFO "Found watch_point %d\n",watchpoint - watchpoints_array);                  \
            clear_##name##_report_info(watchpoint - watchpoints_array);                                              \
            remove_watchpoint(watchpoint);                                                                           \
    }

#endif // CORE_H