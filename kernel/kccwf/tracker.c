#include "tracker.h"
#include "linux/kccwf.h"
#include "linux/types.h"
#include <linux/notifier.h>
#include <linux/xxhash.h>
#include <linux/jhash.h>
#include <linux/lsm_hooks.h>

/* 线程跟踪器哈希表 */
static DEFINE_HASHTABLE(thread_tracker_hash, THREAD_HASH_BITS);
static DEFINE_SPINLOCK(thread_tracker_hash_lock);
atomic_t kccwf_tracker_enable;

/* 线程跟踪器结构 */
struct kccwf_thread_tracker {
	struct hlist_node hash_node;
	pid_t pid;
	int ref;
	struct hlist_head var_hash[1 << VAR_HASH_BITS];
	spinlock_t var_lock;
};

/* 变量跟踪条目 */
struct kccwf_var_entry {
	struct hlist_node hash_node;
	unsigned long var_name;
	struct hlist_head stack_hash[1 << STACK_HASH_BITS];
	spinlock_t stack_lock;
	int entry_count;
};

/* 堆栈跟踪条目 */
struct kccwf_stack_entry {
	struct hlist_node hash_node;
	unsigned long stack_hash;
	atomic_t access_count;
};

unsigned long kccwf_calc_stack_hash(unsigned long *stack, int stack_size)
{
	return xxhash(stack, stack_size * sizeof(unsigned long), 0);
}

// 还得维持个引用计数
int add_tracker(pid_t pid)
{
	struct kccwf_thread_tracker *tracker;
	unsigned long flags;
	int ret = 0;
	spin_lock_irqsave(&thread_tracker_hash_lock, flags);

	// 先检查是否已存在（可能fork的情况）
	hash_for_each_possible(thread_tracker_hash, tracker, hash_node,
			       pid) {
		if (tracker->pid == pid) {
			tracker->ref += 1;
			spin_unlock_irqrestore(&thread_tracker_hash_lock,
					       flags);
			return 0; // 已存在则直接返回
		}
	}

	// 创建新跟踪器
	tracker = kzalloc(sizeof(*tracker), GFP_ATOMIC);
	if (!tracker) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	tracker->pid = pid;
	spin_lock_init(&tracker->var_lock);
	for (int i = 0; i < (1 << VAR_HASH_BITS); i++)
		INIT_HLIST_HEAD(&tracker->var_hash[i]);

	pr_info("[KCCWF]: hook the thread %d\n", pid);
	hash_add(thread_tracker_hash, &tracker->hash_node, pid);

out_unlock:
	spin_unlock_irqrestore(&thread_tracker_hash_lock, flags);
	return ret;
}

/* 释放线程跟踪器资源 */
static void free_tracker(struct kccwf_thread_tracker *tracker)
{
	/* 遍历并释放所有变量条目 */
	for (int i = 0; i < (1 << VAR_HASH_BITS); i++) {
		struct hlist_node *tmp;
		struct kccwf_var_entry *var_entry;

		hlist_for_each_entry_safe(var_entry, tmp, &tracker->var_hash[i],
					  hash_node) {
			/* 遍历并释放所有堆栈条目 */
			for (int j = 0; j < (1 << STACK_HASH_BITS); j++) {
				struct hlist_node *stack_tmp;
				struct kccwf_stack_entry *stack_entry;

				hlist_for_each_entry_safe(
					stack_entry, stack_tmp,
					&var_entry->stack_hash[j], hash_node) {
					hlist_del(&stack_entry->hash_node);
					kfree(stack_entry);
				}
			}
			hlist_del(&var_entry->hash_node);
			kfree(var_entry);
		}
	}
	hlist_del(&tracker->hash_node);
	kfree(tracker);
}

static void kccwf_security_task_free(struct task_struct *task)
{
	kccwf_enable();
	struct kccwf_thread_tracker *tracker;
	unsigned long flags;
	int ret = 0;
	// 先检查是否已存在（可能fork的情况）
	spin_lock_irqsave(&thread_tracker_hash_lock, flags);
	hash_for_each_possible(thread_tracker_hash, tracker, hash_node,
			       task->pid) {
		if (tracker->pid == task->pid) {
			if ((--tracker->ref) == 0){
				pr_info("[KCCWF]: exit the thread %d\n", task->pid);
				free_tracker(tracker);
			}
			break;
		}
	}
	kccwf_enable();
	spin_unlock_irqrestore(&thread_tracker_hash_lock, flags);
}

static int kccwf_security_task_alloc(struct task_struct *task,
				     unsigned long clone_flags)
{
	kccwf_disable();
	struct kccwf_thread_tracker *tracker;
	unsigned long flags;
	int ret = 0;
	spin_lock_irqsave(&thread_tracker_hash_lock, flags);

	// 先检查是否已存在（可能fork的情况）
	hash_for_each_possible(thread_tracker_hash, tracker, hash_node,
			       task->pid) {
		if (tracker->pid == task->pid) {
			tracker->ref += 1;
			spin_unlock_irqrestore(&thread_tracker_hash_lock,
					       flags);
			kccwf_enable();
			return 0; // 已存在则直接返回
		}
	}

	// 创建新跟踪器
	tracker = kzalloc(sizeof(*tracker), GFP_ATOMIC);
	if (!tracker) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	tracker->pid = task->pid;
	spin_lock_init(&tracker->var_lock);
	for (int i = 0; i < (1 << VAR_HASH_BITS); i++)
		INIT_HLIST_HEAD(&tracker->var_hash[i]);

	pr_info("[KCCWF]: hook the thread %d\n", task->pid);
	hash_add(thread_tracker_hash, &tracker->hash_node, task->pid);

out_unlock:
	spin_unlock_irqrestore(&thread_tracker_hash_lock, flags);
	kccwf_enable();
	return ret;
}

static struct security_hook_list kccwf_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(task_free, kccwf_security_task_free),
	LSM_HOOK_INIT(task_alloc, kccwf_security_task_alloc)
};

struct kccwf_thread_tracker *kccwf_get_thread_tracker(pid_t pid)
{
	struct kccwf_thread_tracker *tracker;
	hash_for_each_possible(thread_tracker_hash, tracker, hash_node, pid) {
		if (tracker->pid == pid) {
			return tracker;
		}
	}
	pr_err("[KCCWF]: The tracker of pid %d does not exit!\n", pid);
	return tracker;
}

/* 增加变量访问计数 */
long kccwf_fetch_inc_access_by_stack(unsigned long var_name,
				     unsigned long *stack,
				     unsigned int stack_size)
{
	struct kccwf_thread_tracker *tracker;
	struct kccwf_var_entry *var_entry = NULL;
	struct kccwf_stack_entry *stack_entry = NULL;
	unsigned long stack_hash;
	unsigned long flags;
	int var_hash, stack_hash_idx;
	int ret = 0;

	if (!stack || stack_size == 0)
		return KCCWF_TRACKER_EINVAL;

	tracker = kccwf_get_thread_tracker(current->pid);
	if (IS_ERR(tracker))
		return PTR_ERR(tracker);

	stack_hash = kccwf_calc_stack_hash(stack, stack_size);

	var_hash = var_name % (1 << VAR_HASH_BITS);
	spin_lock_irqsave(&tracker->var_lock, flags);
	hlist_for_each_entry(var_entry, &tracker->var_hash[var_hash],
			     hash_node) {
		if (var_entry->var_name == var_name)
			goto found_var;
	}

	var_entry = kzalloc(sizeof(*var_entry), GFP_ATOMIC);
	if (!var_entry) {
		ret = KCCWF_TRACKER_ENOMEM;
		goto out_unlock_var;
	}
	var_entry->var_name = var_name;
	spin_lock_init(&var_entry->stack_lock);
	for (int i = 0; i < (1 << STACK_HASH_BITS); i++)
		INIT_HLIST_HEAD(&var_entry->stack_hash[i]);
	hlist_add_head(&var_entry->hash_node, &tracker->var_hash[var_hash]);

found_var:
	stack_hash_idx = stack_hash % (1 << STACK_HASH_BITS);
	spin_lock(&var_entry->stack_lock);
	hlist_for_each_entry(stack_entry,
			     &var_entry->stack_hash[stack_hash_idx],
			     hash_node) {
		if (stack_entry->stack_hash == stack_hash) {
			// 加锁了可以不要使用atomic
			atomic_inc(&stack_entry->access_count);
			goto found_stack;
		}
	}

	if (var_entry->entry_count >= MAX_STACK_ENTRIES_PER_SLOT) {
		ret = KCCWF_TRACKER_EFULL;
		goto out_unlock_stack;
	}

	stack_entry = kzalloc(sizeof(*stack_entry), GFP_ATOMIC);
	if (!stack_entry) {
		ret = KCCWF_TRACKER_ENOMEM;
		goto out_unlock_stack;
	}
	stack_entry->stack_hash = stack_hash;
	atomic_set(&stack_entry->access_count, 1);
	hlist_add_head(&stack_entry->hash_node,
		       &var_entry->stack_hash[stack_hash_idx]);
	var_entry->entry_count++;

found_stack:
	spin_unlock(&var_entry->stack_lock);
out_unlock_var:
	spin_unlock_irqrestore(&tracker->var_lock, flags);
	return ret;

out_unlock_stack:
	spin_unlock(&var_entry->stack_lock);
	spin_unlock_irqrestore(&tracker->var_lock, flags);
	return ret;
}

/* 增加变量访问计数 */
int kccwf_fetch_inc_access_by_hash(unsigned long var_name,
				    unsigned long stack_hash)
{
	struct kccwf_thread_tracker *tracker;
	struct kccwf_var_entry *var_entry = NULL;
	struct kccwf_stack_entry *stack_entry = NULL;
	unsigned long flags;
	int var_hash, stack_hash_idx;
	int ret = 0;

	tracker = kccwf_get_thread_tracker(current->pid);
	if (IS_ERR(tracker))
		return PTR_ERR(tracker);

	var_hash = var_name % (1 << VAR_HASH_BITS);
	spin_lock_irqsave(&tracker->var_lock, flags);
	hlist_for_each_entry(var_entry, &tracker->var_hash[var_hash],
			     hash_node) {
		if (var_entry->var_name == var_name)
			goto found_var;
	}

	var_entry = kzalloc(sizeof(*var_entry), GFP_ATOMIC);
	if (!var_entry) {
		ret = KCCWF_TRACKER_ENOMEM;
		goto out_unlock_var;
	}
	var_entry->var_name = var_name;
	spin_lock_init(&var_entry->stack_lock);
	for (int i = 0; i < (1 << STACK_HASH_BITS); i++)
		INIT_HLIST_HEAD(&var_entry->stack_hash[i]);
	hlist_add_head(&var_entry->hash_node, &tracker->var_hash[var_hash]);

found_var:
	stack_hash_idx = stack_hash % (1 << STACK_HASH_BITS);
	spin_lock(&var_entry->stack_lock);
	hlist_for_each_entry(stack_entry,
			     &var_entry->stack_hash[stack_hash_idx],
			     hash_node) {
		if (stack_entry->stack_hash == stack_hash) {
			// 加锁了可以不要使用atomic
			ret = atomic_fetch_inc(&stack_entry->access_count);
			goto found_stack;
		}
	}

	if (var_entry->entry_count >= MAX_STACK_ENTRIES_PER_SLOT) {
		ret = KCCWF_TRACKER_EFULL;
		goto out_unlock_stack;
	}

	stack_entry = kzalloc(sizeof(*stack_entry), GFP_ATOMIC);
	if (!stack_entry) {
		ret = KCCWF_TRACKER_ENOMEM;
		goto out_unlock_stack;
	}
	stack_entry->stack_hash = stack_hash;
	atomic_set(&stack_entry->access_count, 1);
	ret = 1;
	hlist_add_head(&stack_entry->hash_node,
		       &var_entry->stack_hash[stack_hash_idx]);
	var_entry->entry_count++;

found_stack:
	spin_unlock(&var_entry->stack_lock);
out_unlock_var:
	spin_unlock_irqrestore(&tracker->var_lock, flags);
	return ret;

out_unlock_stack:
	spin_unlock(&var_entry->stack_lock);
	spin_unlock_irqrestore(&tracker->var_lock, flags);
	return ret;
}

static struct lsm_id kccwf_lsmid = {
	.name = "kccwf",
	.id = LSM_ID_KCCWF,
};

int kccwf_tracker_init(void)
{
	hash_init(thread_tracker_hash);
	// security_add_hooks(kccwf_hooks, ARRAY_SIZE(kccwf_hooks), &kccwf_lsmid);
	return 0;
}

DEFINE_LSM(kccwf) = { .name = "kccwf", .init = kccwf_tracker_init };

// 增加对hook的删除
void kccwf_tracker_exit(void)
{
	struct kccwf_thread_tracker *tracker;
	struct hlist_node *tmp;
	unsigned long flags;
	int bkt;

	spin_lock_irqsave(&thread_tracker_hash_lock, flags);
	hash_for_each_safe(thread_tracker_hash, bkt, tmp, tracker, hash_node)
		free_tracker(tracker);
	spin_unlock_irqrestore(&thread_tracker_hash_lock, flags);
}

// /* 获取或创建线程跟踪器 */
// struct kccwf_thread_tracker *kccwf_get_thread_tracker(pid_t pid) {
//     struct kccwf_thread_tracker *tracker;
//     unsigned long flags;

//     spin_lock_irqsave(&thread_tracker_hash_lock, flags);
//     /* 查找现有跟踪器 */
//     hash_for_each_possible(thread_tracker_hash, tracker, hash_node, pid) {
//         if (tracker->pid == pid) {
//             spin_unlock_irqrestore(&thread_tracker_hash_lock, flags);
//             return tracker;
//         }
//     }

//     /* 创建新跟踪器 */
//     tracker = kzalloc(sizeof(*tracker), GFP_ATOMIC);
//     if (!tracker) {
//         spin_unlock_irqrestore(&thread_tracker_hash_lock, flags);
//         return ERR_PTR(-ENOMEM);
//     }
//     tracker->pid = pid;
//     spin_lock_init(&tracker->var_lock);
//     for (int i = 0; i < (1 << VAR_HASH_BITS); i++)
//         INIT_HLIST_HEAD(&tracker->var_hash[i]);
//     hash_add(thread_tracker_hash, &tracker->hash_node, pid);
//     spin_unlock_irqrestore(&thread_tracker_hash_lock, flags);
//     return tracker;
// }