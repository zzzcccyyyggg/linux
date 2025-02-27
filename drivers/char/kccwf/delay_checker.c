#include "delay_checker.h"

int stable_logging_phase = 0;
int random_delay_logging_phase = 0;
int checking_sync_phase = 0;
int validating_phase = 0;
delay_var_t global_sync_delay[2];
delay_var_t global_validate_delay[2];

static int checker_open(struct inode *inode, struct file *filp) {
    return 0;
}

static int checker_close(struct inode *inode, struct file *filp) {
    return 0;
}

static long checker_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    int ret;
    switch (cmd) {
	    case CLEAN_LOG:
		    printk(KERN_INFO
			   "[CHECKER_MONITOR] checker_monitor: CLEAN_LOG\n");
		    break;
	    case STOP_LOG:
	        printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: FLUSH_LOG\n");
		    break;
	    case START_CHECKER:
		    printk(KERN_INFO
			   "[CHECKER_MONITOR] checker_monitor: START_CHECKER\n");
		    checker_start = 1;
            break;
        case START_STABLE_LOGGING:
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: START_STABLE_LOGGING\n");
            logger_init();
            stable_logging_phase = 1;
		    checker_start = 1;
            break;
        case STOP_STABLE_LOGGING:
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: STOP_STABLE_LOGGING\n");
            stable_logging_phase = 0;
		    checker_start = 0;
		    logger_exit();
            break;
        case START_RANDOM_DELAY_LOGGING:
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: START_RANDOM_DELAY_LOGGING\n");
            logger_init();
            random_delay_logging_phase = 1;
		    checker_start = 1;
            break;
        case STOP_RANDOM_DELAY_LOGGING:
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: STOP_RANDOM_DELAY_LOGGING\n");
            random_delay_logging_phase = 0;
		    checker_start = 0;
            logger_exit();
		    printk(KERN_INFO "heap_count: %ld\n",
			   atomic_long_read(&heap_count));
		    printk(KERN_INFO "stack_count: %ld\n",
			   atomic_long_read(&stack_count));
            break;
        case START_CHECK_SYNC_PHASE:
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: START_CHECK_SYNC_PHASE\n");
            checking_sync_phase = 1;
            break;
        case COPY_SYNC_STRUCT:
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: COPY_SYNC_STRUCT\n");
            ret = copy_from_user(global_sync_delay, (unsigned char *)arg, 2 * sizeof(delay_var_t));
            if (ret) {
                printk(KERN_WARNING "[CHECKER_MONITOR] checker_monitor: copy_from_user failed\n");
                return -EFAULT;
            }
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: global_sync_delay[0].var_name = %lu\n", global_sync_delay[0].var_name);
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: global_sync_delay[0].call_stack_hash = %lu\n", global_sync_delay[0].call_stack_hash);
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: global_sync_delay[0].delay_time = %d\n", global_sync_delay[0].delay_time);
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: global_sync_delay[1].var_name = %lu\n", global_sync_delay[1].var_name);
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: global_sync_delay[1].call_stack_hash = %lu\n", global_sync_delay[1].call_stack_hash);
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: global_sync_delay[1].delay_time = %d\n", global_sync_delay[1].delay_time);
            break;
        case STOP_CHECK_SYNC_PHASE:
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: STOP_CHECK_SYNC_PHASE\n");
            checking_sync_phase = 0;
            break;
        case START_VALIDATE_PHASE:
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: START_VALIDATE_PHASE\n");
            validating_phase = 1;
            break;
        case COPY_VALIDATE_STRUCT:
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: COPY_VALIDATE_STRUCT\n");
            ret = copy_from_user(global_validate_delay, (unsigned char *)arg, 2 * sizeof(delay_var_t));
            if (ret) {
                printk(KERN_WARNING "[CHECKER_MONITOR] checker_monitor: copy_from_user failed\n");
                return -EFAULT;
            }
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: global_validate_delay[0].var_name = %lu\n", global_validate_delay[0].var_name);
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: global_validate_delay[0].call_stack_hash = %lu\n", global_validate_delay[0].call_stack_hash);
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: global_validate_delay[0].delay_time = %d\n", global_validate_delay[0].delay_time);
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: global_validate_delay[1].var_name = %lu\n", global_validate_delay[1].var_name);
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: global_validate_delay[1].call_stack_hash = %lu\n", global_validate_delay[1].call_stack_hash);
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: global_validate_delay[1].delay_time = %d\n", global_validate_delay[1].delay_time);
            break;
        case STOP_VALIDATE_PHASE:
            printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: STOP_VALIDATE_PHASE\n");
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

static int __init checker_init(void) {
    int result;
    dev_t dev = 0;

    if (mon_major) {
        dev = MKDEV(mon_major, mon_minor);
        result = register_chrdev_region(dev, 1, "checker_monitor");
    } else {
        result = alloc_chrdev_region(&dev, mon_minor, 1, "checker_monitor");
        mon_major = MAJOR(dev);
    }
    if (result < 0) {
        printk(KERN_WARNING "[CHECKER_MONITOR] checker_monitor: can't get major %d\n", mon_major);
        return result;
    }

    checker_dev = (mon_dev_checker_t *)kmalloc(sizeof(mon_dev_checker_t), GFP_KERNEL);
    if (!checker_dev) {
        printk(KERN_WARNING "[CHECKER_MONITOR] checker_monitor: can't allocate memory\n");
        unregister_chrdev_region(dev, 1);
        return -ENOMEM;
    }
    memset(checker_dev, 0, sizeof(mon_dev_checker_t));

    cdev_init(&checker_dev->cdev, &checker_fops);
    checker_dev->cdev.owner = THIS_MODULE;
    checker_dev->cdev.ops = &checker_fops;

    result = cdev_add(&checker_dev->cdev, dev, 1);
    if (result) {
        printk(KERN_WARNING "[CHECKER_MONITOR] checker_monitor: can't add cdev\n");
        kfree(checker_dev);
        unregister_chrdev_region(dev, 1);
        return result;
    }

    // 创建设备类
    checker_class = class_create(CLASS_NAME);
    if (IS_ERR(checker_class)) {
        printk(KERN_WARNING "[CHECKER_MONITOR] checker_monitor: failed to create class\n");
        cdev_del(&checker_dev->cdev);
        kfree(checker_dev);
        unregister_chrdev_region(dev, 1);
        return PTR_ERR(checker_class);
    }

    // 创建设备节点
    checker_device = device_create(checker_class, NULL, dev, NULL, DEVICE_NAME);
    if (IS_ERR(checker_device)) {
        printk(KERN_WARNING "[CHECKER_MONITOR] checker_monitor: failed to create device\n");
        class_destroy(checker_class);
        cdev_del(&checker_dev->cdev);
        kfree(checker_dev);
        unregister_chrdev_region(dev, 1);
        return PTR_ERR(checker_device);
    }

    printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: Checker module loaded\n");
    return 0;
}

static void __exit checker_exit(void) {
    dev_t dev = MKDEV(mon_major, mon_minor);

    device_destroy(checker_class, MKDEV(mon_major, mon_minor)); // 删除设备节点
    class_destroy(checker_class); // 销毁设备类
    cdev_del(&checker_dev->cdev);
    kfree(checker_dev);
    unregister_chrdev_region(dev, 1);

    printk(KERN_INFO "[CHECKER_MONITOR] checker_monitor: Checker module unloaded\n");
}

MODULE_LICENSE("GPL");

module_init(checker_init);
module_exit(checker_exit);