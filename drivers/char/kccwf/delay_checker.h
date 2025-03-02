#ifndef CHECKER_H
#define CHECKER_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/atomic.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/ktime.h>
#include <linux/cdev.h>
#include <linux/io.h>
#include <asm/page.h>
#include <linux/device.h>
#include <linux/kccwf.h>

#define DEV_MAGIC 'c'
#define START_STABLE_LOGGING _IO(DEV_MAGIC, 0)
#define STOP_STABLE_LOGGING _IO(DEV_MAGIC, 1)
#define START_RANDOM_DELAY_LOGGING _IO(DEV_MAGIC, 2)
#define STOP_RANDOM_DELAY_LOGGING _IO(DEV_MAGIC, 3)
#define START_CHECK_SYNC_PHASE _IO(DEV_MAGIC, 4)
#define COPY_SYNC_STRUCT _IOW(DEV_MAGIC, 5, unsigned char)
#define STOP_CHECK_SYNC_PHASE _IO(DEV_MAGIC, 6)
#define START_VALIDATE_PHASE _IO(DEV_MAGIC, 7)
#define COPY_VALIDATE_STRUCT _IOW(DEV_MAGIC, 8, unsigned char)
#define STOP_VALIDATE_PHASE _IO(DEV_MAGIC, 9)
#define START_CHECKER _IO(DEV_MAGIC, 10)
#define STOP_LOG _IO(DEV_MAGIC, 11)
#define CLEAN_LOG _IO(DEV_MAGIC, 12)
#define START_MONITOR _IO(DEV_MAGIC, 13)

#define DEVICE_NAME "checker_monitor"
#define CLASS_NAME "checker_class"

static struct class *checker_class = NULL; // class pointer
static struct device *checker_device = NULL; // device pointer

static int mon_major = 0;
static int mon_minor = 0;

typedef struct mon_dev_checker {
    char *data;
    struct cdev cdev;
} mon_dev_checker_t;

static mon_dev_checker_t *checker_dev;

#endif // CHECKER_H