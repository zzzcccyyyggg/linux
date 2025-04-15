#include "encoding.h"
#include "linux/printk.h"
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/kccwf.h>
#include <linux/stacktrace.h>
#include <asm/unwind.h>
#include <linux/kallsyms.h>
/*
Treat "reading" as a producer and "writing" as a consumer. 
Since the number of consumers is much larger than that of producers, 
and the producer processes the "head" of the ring buffer, 
the number of traversals of subsequent consumers can be reduced. 
Therefore, consider using lock protection for consumers 
and only using atomic variables for error handling for producers.
*/

/* Current problems: cannot ensure the order of the kccwf_access_twbuffer(read access) */
TimeWindowBuffer kccwf_access_twbuffer;

void kccwf_process_write_access(write_access_info_t *write_access_info) {
    unsigned long flags;
    unsigned long write_time = write_access_info->access_time;
    const unsigned long time_threshold = write_time - KCCWF_TIME_WINDOW;
    spin_lock_irqsave(&kccwf_access_twbuffer.lock, flags);

    unsigned long current_head = raw_atomic_long_read(&kccwf_access_twbuffer.head);
    unsigned long current_tail = raw_atomic_long_read(&kccwf_access_twbuffer.tail);

    if (current_head == current_tail) {
        spin_unlock_irqrestore(&kccwf_access_twbuffer.lock, flags);
        return;
    }

    unsigned long valid_start = current_head;
    unsigned long pos = current_head;
    
    // Phase 1: Locating the starting position of valid data
    while (pos != current_tail) {
        read_access_info_t *rec = &kccwf_access_twbuffer.records[pos % KCCWF_RING_BUFFER_SIZE];
        if (rec->access_time >= time_threshold) {
            if (rec->access_time >= write_time) {
                goto exit;
            }else {
                valid_start = pos;
                break;
            }
        }
        pos++;
    }

    // Phase 2: Batch processing of valid records
    while (pos != current_tail) {
        read_access_info_t *rec = &kccwf_access_twbuffer.records[pos % KCCWF_RING_BUFFER_SIZE];
        if (rec->access_time > write_time) break;
        /* [Finish me]: Add the pair to the may_race_pairs */
        if (matching_access((unsigned long)rec->var_addr, rec->size, (unsigned long)write_access_info->var_addr, write_access_info->size)){
            if (rec->tid == write_access_info->tid){
                rec->is_alive = 0;
            }else if(rec->access_time > time_threshold && rec->tid != write_access_info->tid && rec->is_alive){
                if (kccwf_current.kccwf_mode == KCCWF_LOG_MODE){
                    race_pair_t *may_race_pair = kmalloc(sizeof(race_pair_t), GFP_KERNEL);
                    may_race_pair->interval_time = write_access_info->access_time - rec->access_time;
                    may_race_pair->read_name = rec->var_name;
                    may_race_pair->sn = rec->sn;
                    // jump over kccwf_rec_mem_access and kfree
                    sprint_symbol(may_race_pair->funcname_w, rec->stack_entries[2]);
                    printk(KERN_INFO "[KCCWF_LOG_MODE] The read acccess var_name is %lu, addr is %lx,size is %d,the write addr is %lx,the write size is d %d,the interval_time is %lu,the sn is %lu,line num is %d,block num is %d\n",rec->var_name,rec->var_addr,rec->size,write_access_info->var_addr,write_access_info->size,may_race_pair->interval_time,may_race_pair->sn,((rec->file_line >> 16) & 0xffff),((rec->file_line) & 0xffff));
                    if(kccwf_add_may_race_pair(&kccwf_concurrent_pairs, may_race_pair)){    
                        pr_info("===============================Free=======================================\n");
                        pr_info("tid is %d\n",write_access_info->tid);
                        stack_trace_print(write_access_info->stack_entries,write_access_info->num_entries, 0);
                        pr_info("===============================USE=======================================\n");
                        pr_info("tid is %d\n",rec->tid);
                        stack_trace_print(rec->stack_entries,rec->num_entries, 0);
                    }
                }
            }
        }
        pos++;
    }

exit:
    raw_atomic_long_set(&kccwf_access_twbuffer.head, (long)valid_start);
    spin_unlock_irqrestore(&kccwf_access_twbuffer.lock, flags);
}

static int handler_thread_func(void *data) {
    while (kccwf_access_twbuffer.thread_running) {
        wait_event(kccwf_access_twbuffer.wq,kccwf_write_access_buffer.kccwf_write_access_buffer_head < kccwf_write_access_buffer.kccwf_write_access_buffer_tail);
        // printk("the kccwf_write_access_buffer_head is %u,kccwf_write_access_buffer_tail is %u\n",kccwf_write_access_buffer_head,kccwf_write_access_buffer_tail);
        kccwf_process_write_access(&kccwf_write_access_buffer.kccwf_write_access_buffer[(++kccwf_write_access_buffer.kccwf_write_access_buffer_head) % KCCWF_MAX_WRITE_ACCESS_INFOS]);
    }
    return 0;
}

int kccwf_access_twbuffer_init(void) {
    raw_atomic_long_set(&kccwf_access_twbuffer.head, 0);
    raw_atomic_long_set(&kccwf_access_twbuffer.tail, 0);
    init_waitqueue_head(&kccwf_access_twbuffer.wq);
    spin_lock_init(&kccwf_access_twbuffer.lock);
    spin_lock_init(&kccwf_access_twbuffer.read_acccess_lock);
    kccwf_access_twbuffer.thread_running = true;
    kccwf_access_twbuffer.handler_thread = kthread_run(handler_thread_func, NULL, "kccwf_handler");
    if (IS_ERR(kccwf_access_twbuffer.handler_thread)) {
        printk(KERN_ERR "Failed to start handler thread\n");
        return PTR_ERR(kccwf_access_twbuffer.handler_thread);
    }
    return 0;
}

void kccwf_access_twbuffer_clean(void) {
    kccwf_access_twbuffer.thread_running = false;
    wake_up_interruptible(&kccwf_access_twbuffer.wq);
    if (kccwf_access_twbuffer.handler_thread) {
        kthread_stop(kccwf_access_twbuffer.handler_thread);
    }
}

void log_read_access(read_access_info_t* read_access) {
    unsigned long new_tail, write_pos;
    unsigned long flags;
    // [Fix me] tail 追上 head 报错
    new_tail = raw_atomic_long_fetch_inc(&kccwf_access_twbuffer.tail);
    write_pos = new_tail % KCCWF_RING_BUFFER_SIZE;
    smp_wmb();
    
    // 写入数据
    kccwf_access_twbuffer.records[write_pos].access_time = read_access->access_time;
    kccwf_access_twbuffer.records[write_pos].tid = read_access->tid;
    kccwf_access_twbuffer.records[write_pos].var_addr = read_access->var_addr;
    kccwf_access_twbuffer.records[write_pos].var_name = read_access->var_name;
    kccwf_access_twbuffer.records[write_pos].size = read_access->size;
    kccwf_access_twbuffer.records[write_pos].file_line = read_access->file_line;
    kccwf_access_twbuffer.records[write_pos].num_entries = stack_trace_save(kccwf_access_twbuffer.records[write_pos].stack_entries, KCCWF_NUM_STACK_ENTRIES, 1);
    kccwf_access_twbuffer.records[write_pos].is_alive = 1;
    // 更改为根据stack进行count
    kccwf_access_twbuffer.records[write_pos].sn = kccwf_increment_access(read_access->var_name, kccwf_access_twbuffer.records[write_pos].stack_entries, kccwf_access_twbuffer.records[write_pos].num_entries);
}