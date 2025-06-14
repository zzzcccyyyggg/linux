// [Optimize me]: some functions exit may not call which may lead to the some thread legacy in the kccwf_threads_monitored
#include "tracker.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/kccwf.h>

/* global variable */

atomic_t kccwf_threads_monitored[KCCWF_THREADS_MONITORED];

/* static globale variable */

inline int func_call_monitor_init(void){
    kccwf_enable();
    kccwf_disable();
    return 0;
}

inline void func_call_monitor_exit(void){
    kccwf_enable();
    kccwf_disable();
}

void kccwf_rec_func_enter(unsigned long func_name,char func_line) {
	if (current->kccwf_disable_count) {
		return;
    }
    current->kccwf_disable_count++;
    pid_t tid = current->pid;
    atomic_inc(&kccwf_threads_monitored[tid % KCCWF_THREADS_MONITORED]);
    // add_tracker(tid);
    current->kccwf_disable_count--;
}
EXPORT_SYMBOL(kccwf_rec_func_enter);


void kccwf_rec_func_exit(unsigned long func_name, int func_line) {
	if ( current->kccwf_disable_count) {
		return;
    }
    current->kccwf_disable_count++;
    pid_t tid = current->pid;
    atomic_dec(&kccwf_threads_monitored[tid % KCCWF_THREADS_MONITORED]);
    current->kccwf_disable_count--;

}
EXPORT_SYMBOL(kccwf_rec_func_exit);