#include "execution_flow.h"

DEFINE_PER_CPU(struct ccwf_percpu_bbflows, ccwf_percpu_bbflow_vec);
struct block_event *kccwf_rec_bbs_vec;
int kccwf_exec_bbflow_init = false;
unsigned long  ccwf_flow_count = 0;
void init_ccwf_event_list(void) {
    int cpu;
    for_each_possible_cpu(cpu) {
        struct ccwf_percpu_bbflows *pcpu = &per_cpu(ccwf_percpu_bbflow_vec, cpu);
        pcpu->buffer_size = 16 * 1024 * 1024 / sizeof(struct block_event);
        pcpu->buffer = vmalloc(pcpu->buffer_size * sizeof(struct block_event));
        if (!pcpu->buffer) {
            printk(KERN_ERR "Failed to allocate per-CPU buffer for CPU %d\n", cpu);
            return;
        }
        printk(KERN_ERR "Failed to allocate per-CPU buffer for CPU %d\n", cpu);
        pcpu->count = 0;
    }
    printk(KERN_WARNING "Successfully start kccwf rec bbs\n");
}

void cleanup_ccwf_event_list(void) {
    int cpu;

    // 释放每个 CPU 的缓冲区
    for_each_possible_cpu(cpu) {
        struct ccwf_percpu_bbflows *pcpu = &per_cpu(ccwf_percpu_bbflow_vec, cpu);
        if (pcpu->buffer) {
            vfree(pcpu->buffer);
            pcpu->buffer = NULL;
        }
    }
}

bool kccwf_exec_bbflow_enable = false;
void kccwf_rec_bbs(u64 block_id) {
    if (!kccwf_exec_bbflow_enable) return;
    struct ccwf_percpu_bbflows *pcpu;
    unsigned long flags;
    local_irq_disable();       
    pcpu = this_cpu_ptr(&ccwf_percpu_bbflow_vec);

    if (pcpu->count >= pcpu->buffer_size) {
        printk_once(KERN_WARNING "Per-CPU buffer full on CPU %d, count %llu\n", smp_processor_id(),pcpu->count);
        local_irq_enable();
        return;
    }

    pcpu->buffer[pcpu->count].block_id = block_id;
    pcpu->buffer[pcpu->count].timestamp = ktime_get_ns();
    pcpu->count++;

    if (pcpu->count % 100000 == 0) {
        printk(KERN_INFO "CPU %d block count: %lu\n", smp_processor_id(), pcpu->count);
    }

    local_irq_enable();
}