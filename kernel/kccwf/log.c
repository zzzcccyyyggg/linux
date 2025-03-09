#include <linux/kccwf.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>

// 全局动态缓冲区
access_info_t **log_buffer;
DEFINE_PER_CPU(atomic_t, kccwf_log_head); // 每CPU头指针（生产者）
DEFINE_PER_CPU(atomic_t, kccwf_log_tail); // 每CPU尾指针（消费者）
atomic_t overflow_count = ATOMIC_INIT(0);

// 文件操作相关
struct file *log_file;
struct task_struct *bg_thread;

void log_access_info(const access_info_t *var_access_info) {
    current->kccwf_disable_count++;
    int cpu = raw_smp_processor_id();
    atomic_t *phead = per_cpu_ptr(&kccwf_log_head, cpu);
    atomic_t *ptail = per_cpu_ptr(&kccwf_log_tail, cpu);
    int current_head, next_head, current_tail;

    // 使用CAS确保原子更新head
    do {
        current_head = atomic_read(phead);
        next_head = (current_head + 1) % MAX_LOG_ENTRIES;
        current_tail = atomic_read(ptail);

        // 缓冲区满时丢弃最旧数据
        if (next_head == current_tail) {
            atomic_set(ptail, (current_tail + 1) % MAX_LOG_ENTRIES);
            atomic_inc(&overflow_count);
        }
    } while (atomic_cmpxchg(phead, current_head, next_head) != current_head);

    // 写入数据
    log_buffer[cpu][current_head] = *var_access_info;
    smp_wmb(); // 确保数据写入完成
    current->kccwf_disable_count--;
}

void clean_log(void) {
    current->kccwf_disable_count++;
    int cpu;
    for_each_online_cpu(cpu) {
        atomic_set(per_cpu_ptr(&kccwf_log_head, cpu), 0);
        atomic_set(per_cpu_ptr(&kccwf_log_tail, cpu), 0);
    }
    current->kccwf_disable_count--;
}

// 环形缓冲区flush逻辑
int flush_logs(void *arg) {
    current->kccwf_disable_count++;
    int cpu;
    loff_t kccwf_log_file_pos = 0;

    while (!kthread_should_stop()) {
        for_each_online_cpu(cpu) {
            atomic_t *phead = per_cpu_ptr(&kccwf_log_head, cpu);
            atomic_t *ptail = per_cpu_ptr(&kccwf_log_tail, cpu);
            access_info_t *buffer = log_buffer[cpu];
            int saved_head = atomic_read(phead);
            int saved_tail = atomic_read(ptail);
            int entries_to_read;

            if (saved_tail == saved_head)
                continue;

            // 计算待读取条目数
            if (saved_head > saved_tail) {
                entries_to_read = saved_head - saved_tail;
            } else {
                entries_to_read = MAX_LOG_ENTRIES - saved_tail + saved_head;
            }

            // 分块写入
            int first_chunk = (saved_head > saved_tail) ? entries_to_read : (MAX_LOG_ENTRIES - saved_tail);
            if (first_chunk > 0) {
                kernel_write(log_file, &buffer[saved_tail], first_chunk * sizeof(access_info_t), &kccwf_log_file_pos);
            }
            if (entries_to_read > first_chunk) {
                int second_chunk = entries_to_read - first_chunk;
                kernel_write(log_file, buffer, second_chunk * sizeof(access_info_t), &kccwf_log_file_pos);
            }

            // 原子更新tail到当前head位置
            atomic_set(ptail, saved_head);
        }
    }

    current->kccwf_disable_count--;
    return 0;
}

void logger_init(void) {
    current->kccwf_disable_count++;
    printk(KERN_INFO "[LOG] Memory logger initializing\n");
    int cpu;

    log_buffer = kmalloc_array(nr_cpu_ids, sizeof(access_info_t *), GFP_KERNEL);
    if (!log_buffer) {
        pr_err("Failed to allocate log_buffer\n");
        current->kccwf_disable_count--;
        return;
    }

    for_each_possible_cpu(cpu) {
        log_buffer[cpu] = vzalloc(MAX_LOG_ENTRIES * sizeof(access_info_t));
        if (!log_buffer[cpu]) {
            pr_err("Failed to allocate log buffer for CPU %d\n", cpu);
            while (cpu--) vfree(log_buffer[cpu]);
            kfree(log_buffer);
            current->kccwf_disable_count--;
            return;
        }
        atomic_set(per_cpu_ptr(&kccwf_log_head, cpu), 0);
        atomic_set(per_cpu_ptr(&kccwf_log_tail, cpu), 0);
    }

    log_file = filp_open(LOG_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(log_file)) {
        pr_err("Failed to open log file\n");
        for_each_possible_cpu(cpu)
            vfree(log_buffer[cpu]);
        kfree(log_buffer);
        current->kccwf_disable_count--;
        return;
    }

    bg_thread = kthread_run(flush_logs, NULL, "kccwf_flush");
    if (IS_ERR(bg_thread)) {
        pr_err("Failed to start background thread\n");
        filp_close(log_file, NULL);
        for_each_possible_cpu(cpu)
            vfree(log_buffer[cpu]);
        kfree(log_buffer);
        current->kccwf_disable_count--;
        return;
    }

    current->kccwf_disable_count--;
}

void logger_exit(void) {
    current->kccwf_disable_count++;
    int cpu;

    if (bg_thread)
        kthread_stop(bg_thread);

    if (!IS_ERR(log_file))
        filp_close(log_file, NULL);

    if (log_buffer) {
        for_each_possible_cpu(cpu)
            vfree(log_buffer[cpu]);
        kfree(log_buffer);
    }

    pr_info("Memory logger unloaded. Overflow count: %d\n", atomic_read(&overflow_count));
    current->kccwf_disable_count--;
}
