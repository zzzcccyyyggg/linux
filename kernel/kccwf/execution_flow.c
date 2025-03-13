#include "execution_flow.h"
struct ccwf_exec_bbflow_list ccwf_event_list;
int kccwf_exec_bbflow_init = false;
unsigned long  ccwf_flow_count = 0;
void init_ccwf_event_list(void) {
    INIT_LIST_HEAD(&ccwf_event_list.head);
    spin_lock_init(&ccwf_event_list.lock);
    ccwf_event_list.cache = kmem_cache_create(
        "block_exec_flow_cache", 
        sizeof(struct block_event), 
        0, 
        SLAB_HWCACHE_ALIGN, 
        NULL
    );
}

void cleanup_ccwf_event_list(void) {
    struct list_head *pos, *next;
    spin_lock(&ccwf_event_list.lock);
    list_for_each_safe(pos, next, &ccwf_event_list.head) {
        struct block_event *event = list_entry(pos, struct block_event, list);
        list_del(pos);
        kmem_cache_free(ccwf_event_list.cache, event);
    }
    spin_unlock(&ccwf_event_list.lock);
    kmem_cache_destroy(ccwf_event_list.cache);
}

void kccwf_rec_bbs(u64 block_id) {
    // 从SLAB缓存快速分配节点（避免动态内存分配开销）
    if(!kccwf_exec_bbflow_init) init_ccwf_event_list();
    struct block_event *event = kmem_cache_alloc(ccwf_event_list.cache, GFP_ATOMIC);
    if (!event) {
        printk(KERN_WARNING "Failed to allocate block event node!\n");
        return;
    }
    event->timestamp = ktime_get_ns();
    event->block_id = block_id;

    spin_lock(&ccwf_event_list.lock);
    ccwf_flow_count++;
    if (ccwf_flow_count % 100000 == 0){
        printk(KERN_INFO "Flow block count %llu\n",ccwf_flow_count);
    }
    list_add_tail(&event->list, &ccwf_event_list.head);
    spin_unlock(&ccwf_event_list.lock);
}