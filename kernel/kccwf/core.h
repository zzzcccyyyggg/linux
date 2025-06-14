#ifndef KCCWF_CORE_H
#define KCCWF_CORE_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/ktime.h>
#include <linux/delay.h>
#include <linux/kccwf.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include "encoding.h"
#include "report.h"
#include "race_pairs.h"
#include "tracker.h"
#include "wp_checker.h"
#include "race_pairs_monitor.h"

#define INVALID_VALUE 0
#define CONSUMED_VALUE 1
#define PROCESS_VALUE 2
#define REPORTED_VALUE 3

#define PTR_TO_LONG(ptr) ((long)(unsigned long)(ptr))

#define DEFINE_READ_INSTRUMENTED_MEMORY(bits)                          \
	static __always_inline u##bits read_instrumented_memory##bits( \
		const volatile void *addr)                             \
	{                                                              \
		return *(volatile u##bits *)(uintptr_t)addr;           \
	}



#endif // CORE_H