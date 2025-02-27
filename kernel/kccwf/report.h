#ifndef REPORT_H
#define REPORT_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stacktrace.h>
#include <asm/unwind.h>

#define NUM_STACK_ENTRIES 0x40
#ifndef MAX_WATCHPOINTS
#define MAX_WATCHPOINTS 4096
#endif

/* report info */

typedef struct report_info {
    unsigned long stack_entries[NUM_STACK_ENTRIES];
    int num_entries;
    struct task_struct *task;
    unsigned long hash;
    unsigned long var_name;
    int file_line; // in ir file
}report_info_t;

typedef struct reported {
    unsigned long name_1;
    unsigned long name_2;
    int line_1;
    int line_2;
} reported_t;

static DEFINE_RAW_SPINLOCK(report_lock);

static report_info_t read_report_infos[MAX_WATCHPOINTS];
static DEFINE_RAW_SPINLOCK(read_report_lock);

static report_info_t write_report_infos[MAX_WATCHPOINTS];
static DEFINE_RAW_SPINLOCK(write_report_lock);

static reported_t reported_funcs[MAX_WATCHPOINTS];
static reported_t unknown_reported_funcs[MAX_WATCHPOINTS];
static DEFINE_RAW_SPINLOCK(reported_lock);


void set_read_report_info(const volatile void *addr, int is_write, int watchpoint_idx, int file_line , unsigned long var_name);
void set_write_report_info(const volatile void *addr, int is_write, int watchpoint_idx, int file_line ,  unsigned long var_name);
void set_free_report_info(const volatile void *addr, int is_write, int watchpoint_idx, int file_line ,  unsigned long var_name);
void read_report_race(const volatile void *addr, int is_write, int watchpoint_idx, unsigned long func_name, int file_line);
void write_report_race(const volatile void *addr, int is_write, int watchpoint_idx, unsigned long func_name, int file_line);
void clear_read_report_info(int watchpoint_idx);
void clear_write_report_info(int watchpoint_idx);

#define DEFINE_SET_REPORT_INFO_FUNCTION(name, report_infos_array)         \
void set_##name##_report_info(const volatile void *addr, int is_write, int watchpoint_idx, int file_line,unsigned long var_name) { \
    unsigned long flags;                                                                                   \
    raw_spin_lock_irqsave(&report_lock, flags);                                                            \
    struct task_struct *task = current;                                                                \
    report_infos_array[watchpoint_idx].task = task;                                                    \
    report_infos_array[watchpoint_idx].num_entries = stack_trace_save(report_infos_array[watchpoint_idx].stack_entries, NUM_STACK_ENTRIES, 0); \
    report_infos_array[watchpoint_idx].file_line = file_line; \
    report_infos_array[watchpoint_idx].var_name = var_name;                                            \
    raw_spin_unlock_irqrestore(&report_lock, flags);                                                    \
}

#define DEFINE_REPORT_RACE_FUNCTION(name, report_infos_array,report_type)                \
void name##_report_race(const volatile void *addr, int is_write, int watchpoint_idx,                     \
                        unsigned long func_name, int file_line) {                                        \
    struct task_struct *task = current;                                                                 \
    struct unwind_state state;                                                                          \
    unsigned long address;                                                                              \
                                                                                                        \
    if (check_reported(func_name, file_line,report_infos_array[watchpoint_idx].var_name,report_infos_array[watchpoint_idx].file_line)) {                                                         \
        return;                                                                                         \
    }                                                                                                   \
                                                                                                        \
    printk(KERN_INFO "%s", report_type);                                             \
    printk(KERN_INFO "VarName %llu, BlockLineNumber %d, IrLineNumber %d, is write %d\n",               \
           func_name, ((file_line >> 16) & 0xffff), (file_line & 0xffff), is_write);                    \
    for (unwind_start(&state, task, NULL, NULL); !unwind_done(&state); unwind_next_frame(&state)) {     \
        address = unwind_get_return_address(&state);                                                   \
        printk(KERN_INFO "Function: %pS\n", (void *)address);                                           \
    }                                                                                                   \
    printk(KERN_INFO "============OTHER_INFO============\n");                                          \
    printk(KERN_INFO "VarName %llu, BlockLineNumber %d, IrLineNumber %d, watchpoint index %d\n",                            \
           report_infos_array[watchpoint_idx].var_name,                                                                                   \
           ((report_infos_array[watchpoint_idx].file_line >> 16) & 0xffff),                              \
           (report_infos_array[watchpoint_idx].file_line & 0xffff), watchpoint_idx);                                     \
    stack_trace_print(report_infos_array[watchpoint_idx].stack_entries,                                 \
                      report_infos_array[watchpoint_idx].num_entries, 0);                               \
    printk(KERN_INFO "=================================\n");                                            \
                                                                                                        \
    push_reported(func_name, file_line,report_infos_array[watchpoint_idx].var_name,report_infos_array[watchpoint_idx].file_line);                                                                \
    return;                                                                                             \
}


#endif // REPORT_H