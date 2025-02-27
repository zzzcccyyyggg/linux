#ifndef UTILS_H
#define UTILS_H

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>

/* swapper process handler */
typedef struct name_list {
    char *name;
    struct list_head list;
} name_list_t;
static LIST_HEAD(pid_0_name_list);
static DEFINE_SPINLOCK(pid_0_name_list_lock);
static unsigned long pid_0_name_list_lock_flags;

int get_thread_id(void);

#endif // UTILS_H