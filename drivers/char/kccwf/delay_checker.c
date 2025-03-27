#include "delay_checker.h"
#include "linux/atomic/atomic-instrumented.h"
#include "linux/kccwf.h"

static void status_cleared(void){
	memset(kccwf_read_access_infos_sn, 0, sizeof(atomic64_t) * KCCWF_MAX_READ_ACCESS_INFOS);
	atomic_set(&kccwf_current.kccwf_validate_times, 0);
	// atomic_long_set(&kccwf_access_twbuffer.head, 0);
	// atomic_long_set(&kccwf_access_twbuffer.tail, 0);
	// kccwf_write_access_buffer_head = 0;
	// kccwf_write_access_buffer_tail = 0;
}
static int checker_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int checker_close(struct inode *inode, struct file *filp)
{
	return 0;
}

static long checker_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	int ret;
	long _write_count,_read_count,_heap_count,_stack_count;

	switch (cmd) {
	case TURN_OFF_KCCWF:
		kccwf_current.kccwf_mode = KCCWF_DISABLE_MODE;
		printk(KERN_INFO
			"[CHECKER_MONITOR] checker_monitor: TURN_OFF_KCCWF\n");
		break;
	case START_MONITOR:
		kccwf_current.kccwf_mode = KCCWF_MONITOR_MODE;
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: START_MONITOR\n");
		break;
	case START_LOG_PHASE:
		status_cleared();
		kccwf_current.kccwf_mode = KCCWF_LOG_MODE;
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: START_LOG_PHASE\n");
		break;
	case START_CHECK_SYNC_PHASE:
		status_cleared();
		kccwf_current.kccwf_mode = KCCWF_CHECK_MODE;
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: START_CHECK_SYNC_PHASE\n");
		break;
	case START_VALIDATE_PHASE:
		status_cleared();
		kccwf_current.kccwf_mode = KCCWF_VALIDATE_MODE;
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: START_VALIDATE_PHASE\n");
		break;
	// case: PRINT_INFO:
	// 	if (KCCWF_DEBUG) {
	// 		_write_count = atomic_long_read(&kccwf_write_count);
	// 		_read_count = atomic_long_read(&kccwf_read_count);
	// 		_stack_count = atomic_long_read(&stack_count);
	// 		_heap_count = atomic_long_read(&heap_count);
	// 		printk(KERN_INFO "[CHECKER_MONITOR] The write point access: %ld, the read point access %ld\n",_write_count,_read_count);
	// 		printk(KERN_INFO "[CHECKER_MONITOR] Stack count: %ld, Heap count %ld\n",_stack_count,_heap_count);
	// 		atomic_long_set(&kccwf_write_count, 0);
	// 		atomic_long_set(&kccwf_read_count, 0);
	// 		atomic_long_set(&stack_count, 0);
	// 		atomic_long_set(&heap_count, 0);
	// 	}
	// 	break;
	}
	return 0;
}

static const struct file_operations checker_fops = {
	.open = checker_open,
	.release = checker_close,
	.unlocked_ioctl = checker_ioctl,
};

#include <linux/ktime.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
// /proc文件接口
static int proc_show_kccwf_stats(struct seq_file *m, void *v)
{
	seq_printf(m, "Condition Check:\n\tTotal Time: %llu ns\n\tCount: %lu\n\tAvg: %llu ns\n",
		atomic_long_read(&kccwf_statistical_var.time_condition_check_total),
		atomic_long_read(&kccwf_statistical_var.count_condition_check),
		atomic_long_read(&kccwf_statistical_var.count_condition_check) ? 
		atomic_long_read(&kccwf_statistical_var.time_condition_check_total) / atomic_long_read(&kccwf_statistical_var.count_condition_check) : 0);
	seq_printf(m, "Preparing Stage:\n\tTotal Time: %llu ns\n\tCount: %lu\n\tAvg: %llu ns\n",
		atomic_long_read(&kccwf_statistical_var.time_preparing_stage),
		atomic_long_read(&kccwf_statistical_var.count_preparing_stage),
		atomic_long_read(&kccwf_statistical_var.count_preparing_stage) ? 
		atomic_long_read(&kccwf_statistical_var.time_preparing_stage) / atomic_long_read(&kccwf_statistical_var.count_preparing_stage) : 0);
	seq_printf(m, "Watching Processsing:\n\tTotal Time: %llu ns\n\tCount: %lu\n\tAvg: %llu ns\n",
		atomic_long_read(&kccwf_statistical_var.time_watchpoint_processing_total),
		atomic_long_read(&kccwf_statistical_var.count_watchpoint_processing_total),
		atomic_long_read(&kccwf_statistical_var.count_watchpoint_processing_total) ? 
		atomic_long_read(&kccwf_statistical_var.time_watchpoint_processing_total) / atomic_long_read(&kccwf_statistical_var.count_watchpoint_processing_total) : 0);
	return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_show_kccwf_stats, NULL);
}

static const struct proc_ops proc_fops = {
    .proc_open = proc_open,       // 改为 proc_open 成员
    .proc_read = seq_read,        // 改为 proc_read
    .proc_lseek = seq_lseek,      // 改为 proc_lseek
    .proc_release = single_release, // 改为 proc_release
};
static int __init checker_init(void)
{
	int result;
	dev_t dev = 0;

	if (mon_major) {
		dev = MKDEV(mon_major, mon_minor);
		result = register_chrdev_region(dev, 1, "checker_monitor");
	} else {
		result = alloc_chrdev_region(&dev, mon_minor, 1,
					     "checker_monitor");
		mon_major = MAJOR(dev);
	}
	if (result < 0) {
		printk(KERN_WARNING
		       "[CHECKER_MONITOR] checker_monitor: can't get major %d\n",
		       mon_major);
		return result;
	}

	checker_dev = (mon_dev_checker_t *)kmalloc(sizeof(mon_dev_checker_t),
						   GFP_KERNEL);
	if (!checker_dev) {
		printk(KERN_WARNING
		       "[CHECKER_MONITOR] checker_monitor: can't allocate memory\n");
		unregister_chrdev_region(dev, 1);
		return -ENOMEM;
	}
	memset(checker_dev, 0, sizeof(mon_dev_checker_t));

	cdev_init(&checker_dev->cdev, &checker_fops);
	checker_dev->cdev.owner = THIS_MODULE;
	checker_dev->cdev.ops = &checker_fops;

	result = cdev_add(&checker_dev->cdev, dev, 1);
	if (result) {
		printk(KERN_WARNING
		       "[CHECKER_MONITOR] checker_monitor: can't add cdev\n");
		kfree(checker_dev);
		unregister_chrdev_region(dev, 1);
		return result;
	}

	// 创建设备类
	checker_class = class_create(CLASS_NAME);
	if (IS_ERR(checker_class)) {
		printk(KERN_WARNING
		       "[CHECKER_MONITOR] checker_monitor: failed to create class\n");
		cdev_del(&checker_dev->cdev);
		kfree(checker_dev);
		unregister_chrdev_region(dev, 1);
		return PTR_ERR(checker_class);
	}

	// 创建设备节点
	checker_device =
		device_create(checker_class, NULL, dev, NULL, DEVICE_NAME);
	if (IS_ERR(checker_device)) {
		printk(KERN_WARNING
		       "[CHECKER_MONITOR] checker_monitor: failed to create device\n");
		class_destroy(checker_class);
		cdev_del(&checker_dev->cdev);
		kfree(checker_dev);
		unregister_chrdev_region(dev, 1);
		return PTR_ERR(checker_device);
	}

	printk(KERN_INFO
	       "[CHECKER_MONITOR] checker_monitor: Checker module loaded\n");
	kccwf_access_twbuffer_init();
	proc_create("kccwf_stats", 0, NULL, &proc_fops);
	return 0;
}

static void __exit checker_exit(void)
{
	remove_proc_entry("kccwf_stats", NULL);
	dev_t dev = MKDEV(mon_major, mon_minor);
	device_destroy(checker_class,
		       MKDEV(mon_major, mon_minor)); // 删除设备节点
	class_destroy(checker_class); // 销毁设备类
	cdev_del(&checker_dev->cdev);
	current->kccwf_disable_count++;
	kfree(checker_dev);
	current->kccwf_disable_count--;
	unregister_chrdev_region(dev, 1);
	printk(KERN_INFO
	       "[CHECKER_MONITOR] checker_monitor: Checker module unloaded\n");
	kccwf_core_exit();
	kccwf_access_twbuffer_clean();
}

MODULE_LICENSE("GPL");

module_init(checker_init);
module_exit(checker_exit);