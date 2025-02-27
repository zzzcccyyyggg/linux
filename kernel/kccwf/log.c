#include <linux/kccwf.h>

// 全局动态缓冲区
access_info_t **log_buffer;
DEFINE_PER_CPU(int, log_index); // 每CPU索引
DEFINE_PER_CPU(int, head);
DEFINE_PER_CPU(int, tail);
atomic_t overflow_count = ATOMIC_INIT(0);

// 文件操作相关
struct file *log_file;

struct task_struct *bg_thread;

void log_access_info(const access_info_t *var_access_info){
    int cpu = raw_smp_processor_id();
    int *pindex = per_cpu_ptr(&log_index, cpu);

    // 检查索引边界
    if (unlikely(*pindex >= MAX_LOG_ENTRIES)) {
        printk(KERN_INFO "Overflow count: %d in cpu %d\n", atomic_read(&overflow_count), cpu);
        atomic_inc(&overflow_count);
        pindex = per_cpu_ptr(&log_index, cpu);
	    printk(KERN_INFO "pindex %d in cpu %d\n", *pindex, cpu);
    }

    // 写入缓冲区
    log_buffer[cpu][*pindex] = *var_access_info;

    // 安全递增索引
    smp_wmb();
    (*pindex)++;
    // int *phead = per_cpu_ptr(&head, cpu);
    // log_buffer[cpu][*phead] = *var_access_info;
    // smp_wmb();
    // *phead = (*phead + 1) % MAX_LOG_ENTRIES;
}

/*********************** 核心功能函数 ***********************/

void clean_log(void)
{
    int cpu;
    for_each_online_cpu(cpu) {
        int *pindex = per_cpu_ptr(&log_index, cpu);
        access_info_t *buffer = log_buffer[cpu];
        if (!*pindex) continue;
        kernel_write(log_file, "", 0, 0);
        *pindex = 0;
    }
}

int flush_logs(void *arg)
{
    int cpu;
    loff_t pos = 8;
    int index = 0;

    while (1) {
	    if (kthread_should_stop()) {
		    return 0;
        }
	    for_each_online_cpu(cpu) {
            int *pindex = per_cpu_ptr(&log_index, cpu);
            if (!*pindex) continue;
            access_info_t *buffer = log_buffer[cpu];
            // 写入文件头标记
            // 批量写入日志
            int index = *pindex;
            smp_mb();
            // *pindex = 0;
            this_cpu_write(log_index, 0);
            printk(KERN_INFO "pindex %d reseted for cpu %d\n", *pindex, cpu);
            kernel_write(log_file, buffer, index * sizeof(access_info_t), &pos);
            // printk("sizeof pos: %ld\n", sizeof(pos));
            printk(KERN_INFO "log written %d index; pos %ld\n", index, pos);
	    }
        kernel_write(log_file, &pos, sizeof(loff_t), 0);
        // printk(KERN_INFO "log flushed\n");
        // for_each_online_cpu(cpu) {
        //     int *phead = per_cpu_ptr(&head, cpu);
        //     int *ptail = per_cpu_ptr(&tail, cpu);
        //     if (*phead == *ptail) continue;
        //     access_info_t *buffer = log_buffer[cpu];
        //     int index = *phead;
        //     smp_mb();
        //     kernel_write(log_file, buffer + *ptail, (index - *ptail) * sizeof(access_info_t), &pos);
        //     *ptail = index;
        // }
	    // kernel_write(log_file, &pos, sizeof(loff_t), 0);
    }
    return 0;
}

void logger_init(void)
{
	printk(KERN_INFO "[LOG] Memory logger initializing\n");
	int cpu;
	// 1. 分配每CPU缓冲区
	printk(KERN_INFO "sizeof access_info_t: %lu\n", sizeof(access_info_t));
	log_buffer = kmalloc_array(nr_cpu_ids, sizeof(access_info_t *), GFP_KERNEL);
	for_each_possible_cpu(cpu) {
		printk(KERN_INFO "cpu: %d\n", cpu);
		log_buffer[cpu] = vzalloc(
			MAX_LOG_ENTRIES * sizeof(access_info_t));
		if (!log_buffer[cpu]) {
			printk(KERN_INFO "Failed to allocate log buffer\n");
			return;
        }
    }
	
    // 2. 初始化索引
    for_each_possible_cpu(cpu)
        *per_cpu_ptr(&log_index, cpu) = 0;

    // 3. 打开日志文件
    log_file = filp_open("/var/log/mem_access.log", 
                       O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (IS_ERR(log_file)) {
        pr_err("Failed to open log file: %ld\n", PTR_ERR(log_file));
        // 清理内存
        return;
    }
    printk(KERN_INFO "[LOG] Opened log file\n");

    if ((bg_thread = kthread_create(flush_logs, NULL, "monitor_background_thread")) < 0) {
        printk(KERN_EMERG "monitor_init: background thread create error\n");
        return;
    }
    // struct sched_param param;
    // param.sched_priority = 99;
    // sched_setscheduler(bg_thread, SCHED_FIFO, &param);
    wake_up_process(bg_thread);
    printk(KERN_INFO "[LOG] Memory logger loaded\n");
}

/*********************** 模块清理 ***********************/
void logger_exit(void)
{
	int cpu;

	kthread_stop(bg_thread);
	
    // 关闭文件
    if (!IS_ERR(log_file))
	    filp_close(log_file, NULL);

    if (log_buffer) {
        for_each_possible_cpu(cpu) {
            if (log_buffer[cpu])
                vfree(log_buffer[cpu]);
        }
        kfree(log_buffer);
    }


    pr_info("Memory logger unloaded. Overflow count: %d\n", atomic_read(&overflow_count));
}