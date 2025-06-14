// 示踪剂
#include "bb_tracer.h"
#include "linux/kccwf.h"
static struct kccwf_bbs_state bbs_states[BB_TRACER_STATE_ARRAY_SIZE];

// 如果当前线程属于测试线程，记录当前测试线程的状态
void kccwf_rec_bbs(uint64_t hash)
{
	tid_t tid = current->pid;
	for (int i = 0; i < kccwf_current.testing_tids.num; i++) {
		if (tid == kccwf_current.testing_tids.tids[i]) {
			kccwf_current.bbs_state[i] = hash;
		}
	}
}

EXPORT_SYMBOL_GPL(kccwf_rec_bbs);

// 获取某一特定测试线程的状态
uint64_t kccwf_query_bbs(pid_t tid)
{
	for (int i = 0; i < kccwf_current.testing_tids.num; i++) {
		if (tid == kccwf_current.testing_tids.tids[i]) {
			return kccwf_current.bbs_state[i];
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kccwf_query_bbs);
