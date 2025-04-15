#ifndef _KCCWF_TRACKER_H
#define _KCCWF_TRACKER_H
#include "linux/atomic/atomic-long.h"
#include "linux/kccwf.h"
#include <linux/xxhash.h>
#include <linux/stacktrace.h>
#include <linux/sched.h>
#include <asm/unwind.h>

struct kccwf_sn_info *kccwf_read_access_infos_sn;


int kccwf_tracker_init(void)
{
    kccwf_read_access_infos_sn = vzalloc(sizeof(kccwf_sn_info_t) * KCCWF_MAX_READ_ACCESS_INFOS);
    if (!kccwf_read_access_infos_sn) 
        return -ENOMEM;

    for (int i = 0; i < KCCWF_MAX_READ_ACCESS_INFOS; i++) {
        INIT_LIST_HEAD(&kccwf_read_access_infos_sn[i].stack_list);
        spin_lock_init(&kccwf_read_access_infos_sn[i].lock);
        kccwf_read_access_infos_sn[i].entry_count = 0;
    }
    return 0;
}

static inline unsigned long calc_stack_hash(unsigned long *stack, int stack_size) {
    return xxhash((u64 *)stack, stack_size * sizeof(unsigned long), 0);
}

unsigned long kccwf_fetch_inc_stack_sn(unsigned long var_name,unsigned long *stack, unsigned int stack_size) {
    kccwf_sn_info_t *info = &kccwf_read_access_infos_sn[var_name];
    unsigned long hash = calc_stack_hash(stack, stack_size);
    struct kccwf_stack_entry *entry;
    spin_lock(&info->lock);
    list_for_each_entry(entry, &info->stack_list, list) {
        if (entry->stack_hash == hash) {
            spin_unlock(&info->lock);
            return raw_atomic_long_fetch_inc(&entry->access_count);
        }
    }
    spin_unlock(&info->lock);
    return 0;
}

struct kccwf_stack_entry *kccwf_find_stack(unsigned long var_name, unsigned long *stack, unsigned int stack_size) {
    kccwf_sn_info_t *info = &kccwf_read_access_infos_sn[var_name];
    unsigned long hash = calc_stack_hash(stack, stack_size);
    struct kccwf_stack_entry *entry;
    
    spin_lock(&info->lock);
    list_for_each_entry(entry, &info->stack_list, list) {
        if (entry->stack_hash == hash) {
            spin_unlock(&info->lock);
            return entry;
        }
    }
    spin_unlock(&info->lock);
    return NULL;
}

long kccwf_increment_access(unsigned long var_name, unsigned long *stack, unsigned int stack_size) {
    kccwf_sn_info_t *info = &kccwf_read_access_infos_sn[var_name];
    unsigned long hash = calc_stack_hash(stack, stack_size);
    long sn = 0;
    struct kccwf_stack_entry *entry;
    bool found = false;

    spin_lock(&info->lock);

    list_for_each_entry(entry, &info->stack_list, list) {
        if (entry->stack_hash == hash) {
            sn = raw_atomic_long_fetch_inc(&entry->access_count);
            found = true;
            break;
        }
    }
    // 未找到且有空位时插入新条目
    if (!found && info->entry_count < MAX_STACK_ENTRIES_PER_SLOT) {
        entry = kmalloc(sizeof(struct kccwf_stack_entry), GFP_ATOMIC);
        if (entry) {
            entry->stack_hash = hash;
            atomic64_set(&entry->access_count, 1);
            INIT_LIST_HEAD(&entry->list);
            list_add_tail(&entry->list, &info->stack_list);
            info->entry_count++;
            sn = 0;
        }
    }
    return sn;
    spin_unlock(&info->lock);
}

void kccwf_tracker_exit(void)
{
    for (int i = 0; i < KCCWF_MAX_READ_ACCESS_INFOS; i++) {
        struct list_head *head = &kccwf_read_access_infos_sn[i].stack_list;
        struct kccwf_stack_entry *entry, *tmp;
        
        spin_lock(&kccwf_read_access_infos_sn[i].lock);
        list_for_each_entry_safe(entry, tmp, head, list) {
            list_del(&entry->list);
            kfree(entry);
        }
        spin_unlock(&kccwf_read_access_infos_sn[i].lock);
    }
    vfree(kccwf_read_access_infos_sn);
}








#endif