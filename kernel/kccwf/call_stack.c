#include "call_stack.h"
#include "core.h"
#include "linux/list.h"

LIST_HEAD(global_thread_chain_head);
DEFINE_SPINLOCK(thread_chain_lock);
unsigned long thread_chain_lock_flags;

__u64 FNV1a_Hash_Ulong(unsigned long value) {
    __u64 hash = FNV_OFFSET_BASIS;
    unsigned char *data = (unsigned char *)&value;

    for (size_t i = 0; i < sizeof(unsigned long); i++) {
        hash ^= (__u64)data[i];
        hash *= FNV_PRIME;
    }

    return hash;
}
// [Fix ME!] This function may cause dead lock
void rec_func_enter(unsigned long func_name, int func_line) {
	// printk(KERN_INFO "[KERNEL_MONITOR] rec_func_enter: %lu, %d\n", func_name, func_line);
	// pid_t tid = get_thread_id();
	if (checker_start != KCCWF_FUZZ_MODE || current->ccwf_disable_count) {
		return;
    }
    pid_t tid = current->pid;

    bool new_thread = true;
    thread_chain_t *tc;
    __u64 hash_1, hash_2;

    func_call_t *fc = (func_call_t *)kzalloc(sizeof(func_call_t), GFP_ATOMIC);
    if (!fc) {
        printk(KERN_WARNING "[KERNEL_MONITOR] kernel_monitor: can't allocate memory\n");
        return;
    }
    fc->func_name = func_name;
    fc->func_line = func_line;

    /* check if is new thread */
    spin_lock_irqsave(&thread_chain_lock, thread_chain_lock_flags);
    list_for_each_entry(tc, &global_thread_chain_head, list) {
        if (tc->tid == tid) {
            new_thread = false;
            break;
        }
    }

    if(new_thread) {
        tc = (thread_chain_t *)kzalloc(sizeof(thread_chain_t), GFP_ATOMIC);
        if (!tc) {
            printk(KERN_WARNING "[KERNEL_MONITOR] kernel_monitor: can't allocate memory\n");
            return;
        }
        tc->tid = tid;
        INIT_LIST_HEAD(&tc->func_calls);
        list_add_tail(&tc->list, &global_thread_chain_head);
    }
    
    list_add_tail(&fc->list, &tc->func_calls);
    if(new_thread) {
        hash_1 = FNV1a_Hash_Ulong(func_name+func_line);
    } else {
        hash_1 = FNV1a_Hash_Ulong(func_name+func_line+list_entry(tc->func_calls.prev, func_call_t, list)->func_call_stack_hash);
    }
    fc->func_call_stack_hash = hash_1;
    tc->thread_call_stack_hash = hash_1;
    spin_unlock_irqrestore(&thread_chain_lock, thread_chain_lock_flags);
}
EXPORT_SYMBOL(rec_func_enter);

void print_call_stack(void) {
    thread_chain_t *tc;
    func_call_t *fc;
    printk(KERN_INFO "[KERNEL_MONITOR] Start print call stack\n");
    list_for_each_entry(tc, &global_thread_chain_head, list) {
        printk(KERN_INFO "[KERNEL_MONITOR] print_call_stack: thread %d\n", tc->tid);
        list_for_each_entry(fc, &tc->func_calls, list) {
            printk(KERN_INFO "[KERNEL_MONITOR] print_call_stack: %lu, %d\n", fc->func_name, fc->func_line);
        }
    }
    printk(KERN_INFO "[KERNEL_MONITOR] End print call stack\n");
}

void rec_func_exit(unsigned long func_name, int func_line) {
	if (checker_start != KCCWF_FUZZ_MODE || current->ccwf_disable_count) {
		return;
    }
    // pid_t tid = get_thread_id();
    pid_t tid = current->pid;
    thread_chain_t *tc, *tmp_tc, *tc_to_free = NULL;
    func_call_t *fc, *tmp_fc, *fc_to_free = NULL;
    __u64 prev_call_stack_hash = 0;
    spin_lock_irqsave(&thread_chain_lock, thread_chain_lock_flags);
    list_for_each_entry_safe(tc, tmp_tc, &global_thread_chain_head, list) {
        if (tc->tid == tid) {
            list_for_each_entry_safe(fc, tmp_fc, &tc->func_calls, list) {
                if (fc->func_name == func_name && fc->func_line == func_line) {
                    prev_call_stack_hash = list_prev_entry(fc, list)->func_call_stack_hash;
                    list_del(&fc->list);
                    fc_to_free = fc;
                    break;
                }
            }
            break;
        }
    }

    // uaf or slab out of bounds
    if(list_empty(&tc->func_calls)) {
	    list_del(&tc->list);
	    tc_to_free = tc;
        // printk(KERN_INFO "[KERNEL_MONITOR] rec_func_exit: thread %d is deleted\n", tid);
    } else {
	    tc->thread_call_stack_hash = prev_call_stack_hash;
        // print_call_stack();
    }
    if(fc_to_free) {
        current->ccwf_disable_count++;
        kfree(fc_to_free);
        current->ccwf_disable_count--;
    }
    if(tc_to_free) {
        current->ccwf_disable_count++;
        kfree(tc_to_free);
        current->ccwf_disable_count--;
    }
    spin_unlock_irqrestore(&thread_chain_lock, thread_chain_lock_flags);

}
EXPORT_SYMBOL(rec_func_exit);