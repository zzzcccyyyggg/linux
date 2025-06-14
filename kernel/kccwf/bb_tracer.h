#include <linux/module.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/slab.h>

#define BB_TRACER_STATE_ARRAY_SIZE 0X1000

// iocttl 可控的当前测试tid


struct kccwf_bbs_state {
    uint64_t index;
    uint64_t hash;
};
