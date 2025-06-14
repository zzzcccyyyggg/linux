#include "ctl_dev.h"
#include "linux/kccwf.h"
may_race_pair_list_t g_may_race_pair_list;

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
	long _write_count, _read_count, _heap_count, _stack_count;

	switch (cmd) {
	case TURN_OFF_KCCWF:
		kccwf_current.mode = KCCWF_DISABLE_MODE;
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: TURN_OFF_KCCWF\n");
		break;
	case START_MONITOR:
		kccwf_current.mode = KCCWF_MONITOR_MODE;
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: START_MONITOR\n");
		break;
	case START_LOG_PHASE:
		kccwf_current.mode = KCCWF_LOG_MODE;
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: START_LOG_PHASE\n");
		break;
	case START_CHECK_SYNC_PHASE:
		kccwf_current.mode = KCCWF_CHECK_MODE;
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: START_CHECK_SYNC_PHASE\n");
		break;
	case START_VALIDATE_PHASE:
		kccwf_current.mode = KCCWF_VALIDATE_MODE;
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: START_VALIDATE_PHASE\n");
		break;
	case MODIFY_TESTING_TID: {
		kccwf_testing_tids_t tids;
		if (copy_from_user(&tids, (kccwf_testing_tids_t *)arg,
				   sizeof(kccwf_testing_tids_t))) {
			return -EFAULT;
		}
		if (tids.num > KCCWF_MAX_TESTING_TID_NUM) {
			return -EINVAL;
		}
		memcpy(kccwf_current.testing_tids.tids, tids.tids,
		       sizeof(tids.tids));
		kccwf_current.testing_tids.num = tids.num;
		printk(KERN_INFO
		       "[CHECKER_MONITOR] checker_monitor: MODIFY_TESTING_TID\n");
		break;
	}
	case SET_MAY_RACE_PAIRS: {
		may_race_pair_list_t user_list;
		if (copy_from_user(&user_list, (void __user *)arg,
				   sizeof(user_list))) {
			return -EFAULT;
		}
		if (user_list.num > MAX_RACE_PAIR_NUM) {
			return -EINVAL;
		}

		printk(KERN_INFO
		       "[CHECKER_MONITOR] SET_MAY_RACE_PAIRS received %u pairs\n",
		       user_list.num);
		for (uint32_t i = 0; i < user_list.num; ++i) {
			printk(KERN_INFO "  Pair %u: (%lx, %lx, %lx, %lx)\n", i,
			       user_list.pairs[i].var_name_1,
			       user_list.pairs[i].var_name_2,
			       user_list.pairs[i].call_stack_hash_1,
			       user_list.pairs[i].call_stack_hash_2);
		}

		// 保存到全局变量
		memcpy(&g_may_race_pair_list, &user_list, sizeof(user_list));
		break;
	}
	case GET_MAY_RACE_PAIRS: {
		if (copy_to_user((void __user *)arg, &g_may_race_pair_list,
				 sizeof(g_may_race_pair_list))) {
			return -EFAULT;
		}
		printk(KERN_INFO
		       "[CHECKER_MONITOR] GET_MAY_RACE_PAIRS sent %u pairs\n",
		       g_may_race_pair_list.num);
		break;
	}
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
	seq_printf(
		m,
		"Condition Check:\n\tTotal Time: %llu ns\n\tCount: %lu\n\tAvg: %llu ns\n",
		atomic_long_read(
			&kccwf_statistical_var.time_condition_check_total),
		atomic_long_read(&kccwf_statistical_var.count_condition_check),
		atomic_long_read(&kccwf_statistical_var.count_condition_check) ?
			atomic_long_read(&kccwf_statistical_var
						  .time_condition_check_total) /
				atomic_long_read(
					&kccwf_statistical_var
						 .count_condition_check) :
			0);
	seq_printf(
		m,
		"Preparing Stage:\n\tTotal Time: %llu ns\n\tCount: %lu\n\tAvg: %llu ns\n",
		atomic_long_read(&kccwf_statistical_var.time_preparing_stage),
		atomic_long_read(&kccwf_statistical_var.count_preparing_stage),
		atomic_long_read(&kccwf_statistical_var.count_preparing_stage) ?
			atomic_long_read(
				&kccwf_statistical_var.time_preparing_stage) /
				atomic_long_read(
					&kccwf_statistical_var
						 .count_preparing_stage) :
			0);
	seq_printf(
		m,
		"Watching Processsing:\n\tTotal Time: %llu ns\n\tCount: %lu\n\tAvg: %llu ns\n",
		atomic_long_read(
			&kccwf_statistical_var.time_watchpoint_processing_total),
		atomic_long_read(&kccwf_statistical_var
					  .count_watchpoint_processing_total),
		atomic_long_read(&kccwf_statistical_var
					  .count_watchpoint_processing_total) ?
			atomic_long_read(
				&kccwf_statistical_var
					 .time_watchpoint_processing_total) /
				atomic_long_read(
					&kccwf_statistical_var
						 .count_watchpoint_processing_total) :
			0);
	return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_show_kccwf_stats, NULL);
}

static const struct proc_ops proc_fops = {
	.proc_open = proc_open, // 改为 proc_open 成员
	.proc_read = seq_read, // 改为 proc_read
	.proc_lseek = seq_lseek, // 改为 proc_lseek
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
}

MODULE_LICENSE("GPL");

module_init(checker_init);
module_exit(checker_exit);