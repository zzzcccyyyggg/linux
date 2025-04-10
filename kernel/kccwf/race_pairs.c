#include <linux/kccwf.h>

kccwf_concurrent_pairs_t kccwf_concurrent_pairs;

static void list_add_safe(struct list_head *head, 
    race_pair_t *race_pair,
    spinlock_t *lock)
{
    struct race_pair_entry *entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    entry->race_pair = *race_pair;
    unsigned long flags;
    spin_lock_irqsave(lock, flags);
    list_add_tail(&entry->list, head);
    spin_unlock_irqrestore(lock, flags);
}

void kccwf_add_may_race_pair(kccwf_concurrent_pairs_t *pairs, race_pair_t *pair)
{
    list_add_safe(&pairs->may_race_list, pair, &pairs->may_race_lock);
}

void kccwf_add_checked_race_pair(kccwf_concurrent_pairs_t *pairs, race_pair_t *pair)
{
    list_add_safe(&pairs->checked_race_list, pair, &pairs->checked_race_lock);
}

/* 查找函数（线程安全）*/
struct race_pair_entry *kccwf_find_race_pair(
    struct list_head *head, 
    spinlock_t *lock,
    const race_pair_t *target,
    bool (*cmp)(const race_pair_t *, const race_pair_t *))
{
    struct race_pair_entry *pos;
    unsigned long flags;
    
    spin_lock_irqsave(lock, flags);
    list_for_each_entry(pos, head, list) {
        if (cmp(&pos->race_pair, target)) {
            spin_unlock_irqrestore(lock, flags);
            return pos; // 找到匹配项
        }
    }
    spin_unlock_irqrestore(lock, flags);
    return NULL; // 未找到
}

static void delete_race_pair(
    struct list_head *head,
    spinlock_t *lock,
    const race_pair_t *target,
    bool (*cmp)(const race_pair_t *, const race_pair_t *)) 
{
    struct race_pair_entry *pos, *n;
    unsigned long flags;
    
    spin_lock_irqsave(lock, flags);
    list_for_each_entry_safe(pos, n, head, list) {
        if (cmp(&pos->race_pair, target)) {
            list_del(&pos->list);    // 从链表移除
            kfree(pos);             // 释放内存
            break;
        }
    }
    spin_unlock_irqrestore(lock, flags);
}

bool kccwf_race_pair_cmp(const race_pair_t *a, const race_pair_t *b) {
    return a->read_name == b->read_name && 
           a->sn == b->sn;
}

bool kccwf_race_pair_cmp_by_varname(const race_pair_t *a, const race_pair_t *b){
    return a->read_name == b->read_name;
}

void kccwf_remove_race_pair(
    kccwf_concurrent_pairs_t *pairs, 
    const race_pair_t *pair,
    bool (*cmp)(const race_pair_t *, const race_pair_t *))
{
    delete_race_pair(&pairs->may_race_list, &pairs->may_race_lock, pair, cmp);
}



void kccwf_concurrent_pairs_init(kccwf_concurrent_pairs_t *pairs) {
    INIT_LIST_HEAD(&pairs->may_race_list);
    INIT_LIST_HEAD(&pairs->no_sync_race_list);
    INIT_LIST_HEAD(&pairs->checked_race_list);
    
    spin_lock_init(&pairs->may_race_lock);
    spin_lock_init(&pairs->no_sync_race_lock);
    spin_lock_init(&pairs->checked_race_lock);
}
