#ifndef KCCWF_CTL_DEV_H
#define KCCWF_CTL_DEV_H

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
#define TURN_OFF_KCCWF _IO(DEV_MAGIC, 0)
#define START_MONITOR _IO(DEV_MAGIC, 1)
#define START_LOG_PHASE _IO(DEV_MAGIC, 2)
#define START_CHECK_SYNC_PHASE _IO(DEV_MAGIC, 3)
#define START_VALIDATE_PHASE _IO(DEV_MAGIC, 4)
#define MODIFY_TESTING_TID _IOW(DEV_MAGIC, 5, kccwf_testing_tids_t)
#define SET_MAY_RACE_PAIRS _IOW(DEV_MAGIC, 6, may_race_pair_list)
#define GET_MAY_RACE_PAIRS _IOR(DEV_MAGIC, 6, may_race_pair_list)

#define DEVICE_NAME "kccwf_ctl_dev"
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

#endif // KCCWF_CTL_EQP_H