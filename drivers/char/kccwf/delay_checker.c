#include "delay_checker.h"
#include "linux/printk.h"
#include "linux/stddef.h"

int stable_logging_phase = 0;
int random_delay_logging_phase = 1;
int checking_sync_phase = 0;
int validating_phase = 0;
delay_var_t global_sync_delay[2];
delay_var_t global_validate_delay[256];
int is_log_init = 0;
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
	case CLEAN_LOG:
		// kccwf_log_file_clean = true;
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: CLEAN_LOG\n");
		break;
	case STOP_LOG:
		TURN_OFF_LOG(kccwf_mode);
		if (KCCWF_DEBUG) {
			_write_count = atomic_long_read(&kccwf_write_count);
			_read_count = atomic_long_read(&kccwf_read_count);
			_stack_count = atomic_long_read(&stack_count);
			_heap_count = atomic_long_read(&heap_count);
			printk(KERN_INFO "[CHECKER_MONITOR] The write point access: %ld, the read point access %ld\n",_write_count,_read_count);
			printk(KERN_INFO "[CHECKER_MONITOR] Stack count: %ld, Heap count %ld\n",_stack_count,_heap_count);
			atomic_long_set(&kccwf_write_count, 0);
			atomic_long_set(&kccwf_read_count, 0);
			atomic_long_set(&stack_count, 0);
			atomic_long_set(&heap_count, 0);
		}
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: STOP LOG\n");
		break;
	case START_FUZZER:
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: START_CHECKER\n");
		break;
	case START_MONITOR:
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: START_MONITOR\n");
		kccwf_mode = KCCWF_MONITOR_MODE;
		break;
	case START_STABLE_LOGGING:
		if (!is_log_init){
			logger_init();
			is_log_init = true;
		}
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: START_STABLE_LOGGING\n");
		kccwf_mode = KCCWF_STABLE_SAMPLING;
		break;
	case STOP_STABLE_LOGGING:
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: STOP_STABLE_LOGGING\n");

		kccwf_mode = KCCWF_MONITOR_MODE;
		break;
	case START_RANDOM_DELAY_LOGGING:
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: START_RANDOM_DELAY_LOGGING\n");
		kccwf_mode = KCCWF_RANDOM_SAMPLING;
		break;
	case STOP_RANDOM_DELAY_LOGGING:
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: STOP_RANDOM_DELAY_LOGGING\n");
		kccwf_mode = KCCWF_MONITOR_MODE;
		break;
	case START_CHECK_SYNC_PHASE:
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: START_CHECK_SYNC_PHASE\n");
		checking_sync_phase = 1;
		break;
	case COPY_SYNC_STRUCT:
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: COPY_SYNC_STRUCT\n");
		ret = copy_from_user(global_sync_delay, (unsigned char *)arg,
				     2 * sizeof(delay_var_t));
		if (ret) {
			printk(KERN_WARNING
			       "[CHECKER_MONITOR] checker_monitor: copy_from_user failed\n");
			return -EFAULT;
		}
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: global_sync_delay[0].var_name = %lu\n",
		       global_sync_delay[0].var_name);
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: global_sync_delay[0].call_stack_hash = %lu\n",
		       global_sync_delay[0].call_stack_hash);
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: global_sync_delay[0].delay_time = %d\n",
		       global_sync_delay[0].delay_time);
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: global_sync_delay[1].var_name = %lu\n",
		       global_sync_delay[1].var_name);
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: global_sync_delay[1].call_stack_hash = %lu\n",
		       global_sync_delay[1].call_stack_hash);
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: global_sync_delay[1].delay_time = %d\n",
		       global_sync_delay[1].delay_time);
		break;
	case STOP_CHECK_SYNC_PHASE:
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: STOP_CHECK_SYNC_PHASE\n");
		checking_sync_phase = 0;
		break;
	case START_VALIDATE_PHASE:
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: START_VALIDATE_PHASE\n");
		validating_phase = 1;
		break;
	case COPY_VALIDATE_STRUCT:
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: COPY_VALIDATE_STRUCT\n");
		ret = copy_from_user(global_validate_delay,
				     (unsigned char *)arg,
				     256 * sizeof(delay_var_t));
		if (ret) {
			printk(KERN_WARNING
			       "[CHECKER_MONITOR] checker_monitor: copy_from_user failed\n");
			return -EFAULT;
		}
		break;
	case PRINT_MAYRACEPAIR:
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: PRINT_MAYRACEPAIR\n");
		for (int i = 0;i < 256;i++){
			if (global_validate_delay[i].var_name != 0 && global_validate_delay[i+1].delay_time != 0){ 
				printk(KERN_INFO "var_name: %lu, call_stack_hash: %lu, delay_time: %d\n",
					global_validate_delay[i].var_name,
					global_validate_delay[i].call_stack_hash,
					global_validate_delay[i].delay_time);
			}else{
				break;
			}
		}
		break;
	case STOP_VALIDATE_PHASE:
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: STOP_VALIDATE_PHASE\n");
		validating_phase = 0;
		break;
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
		atomic_long_read(&time_condition_check_total),
		atomic_long_read(&count_condition_check),
		atomic_long_read(&count_condition_check) ? 
		atomic_long_read(&time_condition_check_total) / atomic_long_read(&count_condition_check) : 0);
	
	seq_printf(m, "Stack/Heap Check:\n\tTotal Time: %llu ns\n\tCount: %lu\n\tAvg: %llu ns\n",
		atomic_long_read(&time_stack_heap_total),
		atomic_long_read(&count_stack_heap),
		atomic_long_read(&count_stack_heap) ? 
		atomic_long_read(&time_stack_heap_total) / atomic_long_read(&count_stack_heap) : 0);

	seq_printf(m, "RW Counters:\n\tTotal Time: %llu ns\n\tCount: %lu\n\tAvg: %llu ns\n",
		atomic_long_read(&time_rw_counters_total),
		atomic_long_read(&count_rw_counters),
		atomic_long_read(&count_rw_counters) ? 
		atomic_long_read(&time_rw_counters_total) / atomic_long_read(&count_rw_counters) : 0);

	seq_printf(m, "Get Time/TID:\n\tTotal Time: %llu ns\n\tCount: %lu\n\tAvg: %llu ns\n",
		atomic_long_read(&time_get_time_tid_total),
		atomic_long_read(&count_get_time_tid),
		atomic_long_read(&count_get_time_tid) ? 
		atomic_long_read(&time_get_time_tid_total) / atomic_long_read(&count_get_time_tid) : 0);

	seq_printf(m, "Delay Calculation:\n\tTotal Time: %llu ns\n\tCount: %lu\n\tAvg: %llu ns\n",
		atomic_long_read(&time_delay_calculation_total),
		atomic_long_read(&count_delay_calculation),
		atomic_long_read(&count_delay_calculation) ? 
		atomic_long_read(&time_delay_calculation_total) / atomic_long_read(&count_delay_calculation) : 0);

	seq_printf(m, "Access Info Setup:\n\tTotal Time: %llu ns\n\tCount: %lu\n\tAvg: %llu ns\n",
		atomic_long_read(&time_access_info_setup_total),
		atomic_long_read(&count_access_info_setup),
		atomic_long_read(&count_access_info_setup) ? 
		atomic_long_read(&time_access_info_setup_total) / atomic_long_read(&count_access_info_setup) : 0);

	seq_printf(m, "Watchpoint Processing:\n\tTotal Time: %llu ns\n\tCount: %lu\n\tAvg: %llu ns\n",
		atomic_long_read(&time_watchpoint_processing_total),
		atomic_long_read(&count_watchpoint_processing),
		atomic_long_read(&count_watchpoint_processing) ? 
		atomic_long_read(&time_watchpoint_processing_total) / atomic_long_read(&count_watchpoint_processing) : 0);

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
	// logger_init();
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
	logger_exit();
}

MODULE_LICENSE("GPL");

module_init(checker_init);
module_exit(checker_exit);