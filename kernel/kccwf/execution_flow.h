#ifndef KCCWF_EXEC_FLOW
#define KCCWF_EXEC_FLOW

#include <linux/kccwf.h>
#include <linux/list.h>  // 确保包含链表头文件


extern struct ccwf_exec_bbflow_list ccwf_event_list;  // 声明全局变量
DECLARE_PER_CPU(struct ccwf_percpu_bbflows, ccwf_percpu_bbflow_vec);

#endif /* KCCWF_EXEC_FLOW */