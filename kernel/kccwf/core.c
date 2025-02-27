#include "core.h"

static atomic_long_t read_watchpoints[MAX_WATCHPOINTS];
static atomic_long_t write_watchpoints[MAX_WATCHPOINTS];
static atomic_t may_race_pair_trigger_flag = ATOMIC_INIT(0);
static atomic_t validate_race_pair_trigger_flag = ATOMIC_INIT(0);

DEFINE_READ_INSTRUMENTED_MEMORY(8)
DEFINE_READ_INSTRUMENTED_MEMORY(16)
DEFINE_READ_INSTRUMENTED_MEMORY(32)
DEFINE_READ_INSTRUMENTED_MEMORY(64)
static u64 read_instrumented_memory(const volatile void *addr, int type) {
    switch ((type >> 28) & 0xf) {
    case 1:
        return read_instrumented_memory8(addr);
    case 2:
        return read_instrumented_memory16(addr);
    case 4:
        return read_instrumented_memory32(addr);
    case 8:
        return read_instrumented_memory64(addr);
    default:
        return *(volatile u8 *)(uintptr_t)addr;
    }
}

DEFINE_FIND_WATCHPOINT_FUNCTION(find_write_watchpoint, write_watchpoints)
DEFINE_FIND_WATCHPOINT_FUNCTION(find_read_watchpoint, read_watchpoints)

DEFINE_INSERT_WATCHPOINT_FUNCTION(insert_read_watchpoint, read_watchpoints)
DEFINE_INSERT_WATCHPOINT_FUNCTION(insert_write_watchpoint, write_watchpoints)

// 将其设置为 CONSUMED_VALUE 并返回其原来的值
static long consume_watchpoint(atomic_long_t *watchpoint) {
    return atomic_long_xchg_relaxed(watchpoint, CONSUMED_VALUE);
}

static void remove_watchpoint(atomic_long_t *watchpoint) {
    atomic_long_set(watchpoint, INVALID_VALUE);
}


static bool try_consume_watchpoint(atomic_long_t *watchpoint, long found_addr) {
    return atomic_long_try_cmpxchg_relaxed(watchpoint, &found_addr, CONSUMED_VALUE);
}

DEFINE_SETUP_WATCHPOINT_FUNCTION(read, read_watchpoints)
DEFINE_SETUP_WATCHPOINT_FUNCTION(write, write_watchpoints)

DEFINE_FOUND_WATCHPOINT_FUNCTION(read, read_watchpoints)
DEFINE_FOUND_WATCHPOINT_FUNCTION(write, write_watchpoints)

unsigned long get_current_thread_hash(pid_t tid) {
    unsigned long hash = 0;
    thread_chain_t *tc, *tmp;
    func_call_t *fc;
    spin_lock_irqsave(&thread_chain_lock, thread_chain_lock_flags);
    list_for_each_entry_safe(tc, tmp, &global_thread_chain_head, list) {
        if (tc->tid == tid) {
            hash = tc->thread_call_stack_hash;
            break;
        }
    }
    spin_unlock_irqrestore(&thread_chain_lock, thread_chain_lock_flags);
    return hash;
}

// static void log_access_info(const access_info_t *var_access_info)
// {
//     trace_printk("Access info:  %p,  %d,  %lu,  %d,  %d,  %lu,  %d,  %lu,  %d,  %d\n",
//                  var_access_info->var_addr, var_access_info->is_write, var_access_info->var_name, var_access_info->file_line, var_access_info->type, var_access_info->access_time, var_access_info->tid, var_access_info->call_stack_hash, var_access_info->delay_time, var_access_info->is_skip);
// }

static int in_race_pair(access_info_t var_access_info) {
    if(global_sync_delay[0].var_name == var_access_info.var_name && global_sync_delay[0].call_stack_hash == var_access_info.call_stack_hash) {
        // 会返回当前值
        if(!atomic_cmpxchg(&may_race_pair_trigger_flag,0,1)){
            return global_sync_delay[0].delay_time;
        }
        return 0;
    } else if(global_sync_delay[1].var_name == var_access_info.var_name && global_sync_delay[1].call_stack_hash == var_access_info.call_stack_hash) {
        if(!atomic_cmpxchg(&may_race_pair_trigger_flag,0,1)){
            return global_sync_delay[1].delay_time;
        }
        return 0;
    } else {
        return -1;
    }
}

static int in_validate_pair(access_info_t var_access_info) {
    if(global_validate_delay[0].var_name == var_access_info.var_name && global_validate_delay[0].call_stack_hash == var_access_info.call_stack_hash) {
        if(!atomic_cmpxchg(&validate_race_pair_trigger_flag,0,1)){
            return global_sync_delay[0].delay_time;
        }
        return 0;
    } else if(global_validate_delay[1].var_name == var_access_info.var_name && global_validate_delay[1].call_stack_hash == var_access_info.call_stack_hash) {
        if(!atomic_cmpxchg(&validate_race_pair_trigger_flag,0,1)){
            return global_sync_delay[1].delay_time;
        }
        return 0;
    } else {
        return -1;
    }
}


atomic_long_t heap_count;
atomic_long_t stack_count;

int is_stack_pointer(unsigned long addr) {
	// if(in_softirq() || in_irq()) {
    //     unsigned long irq_stack_start = (unsigned long)per_cpu(pcpu_hot.hardirq_stack_ptr, raw_smp_processor_id()) + 8 - IRQ_STACK_SIZE;
	//     unsigned long irq_stack_end = irq_stack_start + IRQ_STACK_SIZE;
    //     return addr >= irq_stack_start && addr < irq_stack_end;
	// } else {
	//     unsigned long stack_start = (unsigned long)current->stack;
	//     unsigned long stack_end = stack_start + THREAD_SIZE;
	//     return ;
	// }
	// fix me
    unsigned long irq_stack_start = (unsigned long)per_cpu(pcpu_hot.hardirq_stack_ptr, raw_smp_processor_id()) + 8 - IRQ_STACK_SIZE;
	unsigned long irq_stack_end = irq_stack_start + IRQ_STACK_SIZE;
    unsigned long stack_start = (unsigned long)current->stack;
    unsigned long stack_end = stack_start + THREAD_SIZE;
    return (addr >= irq_stack_start && addr < irq_stack_end) || (addr >= stack_start && addr < stack_end);
	
}

void rec_mem_access(const volatile void *addr, unsigned long var_name, int is_write, int file_line, int type) {
	if (!checker_start) {
		return;
    }
    // fix me 
    if (!addr){
        return;
    }
    if (is_stack_pointer((unsigned long)addr)) {
	    atomic_long_inc(&stack_count);
	    return;
    } else {
        atomic_long_inc(&heap_count);
    }
    access_info_t stack_pointer;
    if (!is_stack_pointer((unsigned long)&stack_pointer)) {
        unsigned long irq_stack_start = (unsigned long)per_cpu(pcpu_hot.hardirq_stack_ptr, raw_smp_processor_id()) + 8 - IRQ_STACK_SIZE;
	    unsigned long irq_stack_end = irq_stack_start + IRQ_STACK_SIZE;
	    printk(KERN_INFO "irq_stack_start: %lx\n", irq_stack_start);
	    printk(KERN_INFO "irq_stack_end: %lx\n", irq_stack_end);
        printk(KERN_INFO "stack_pointer: %lx\n", &stack_pointer);
	    dump_stack();
        printk(KERN_INFO "stack_pointer in stack: 0\n");
        printk(KERN_INFO "in_irq: %d\n", in_irq());
        printk(KERN_INFO "in_softirq: %d\n", in_softirq());
    }
    // void *kmalloc_pointer = kmalloc(sizeof(access_info_t), GFP_KERNEL);
    // printk(KERN_INFO "kmalloc_pointer: %lx\n", kmalloc_pointer);
    // struct kmem_cache *my_cache = kmem_cache_create("my_test_cache", sizeof(access_info_t), 0,
	// 			 SLAB_HWCACHE_ALIGN, NULL);
    // void *kmem_cache_alloc_pointer = kmem_cache_alloc(my_cache, GFP_KERNEL);
    // printk(KERN_INFO "kmem_cache_alloc_pointer: %lx\n",
	//    kmem_cache_alloc_pointer);
    // kfree(kmalloc_pointer);
    // kmem_cache_free(my_cache, kmem_cache_alloc_pointer);
    ktime_t access_time = ktime_get();
    pid_t tid = current->pid;
    unsigned long call_stack_hash = get_current_thread_hash(tid);
    int delay_time = 0;
    if(stable_logging_phase) {
        delay_time = 0;
    } else if(random_delay_logging_phase) {
        if(get_random_u32_below(100) < DELAY_PROBABILITY){
            delay_time = get_random_u32_below(80);
        }else{
            delay_time = 0;
        }
    }

    access_info_t var_access_info = {
        .is_write = is_write,
        .file_line = file_line,
        .var_name = var_name,
        .type = type,
        .var_addr = addr,
        .call_stack_hash = call_stack_hash,
        .access_time = access_time,
        .tid = tid,
        .delay_time = delay_time,
        .is_skip = 0
    };

    if(stable_logging_phase || random_delay_logging_phase) {
        log_access_info(&var_access_info);
    } else if(checking_sync_phase) {
        delay_time = in_race_pair(var_access_info);
        if(delay_time != -1) {
            // the race variable happens first, so delay the access
            log_access_info(&var_access_info);
        } else {
            return;
        }
    }

    if(validating_phase) {
        delay_time = in_validate_pair(var_access_info);
        if(delay_time != -1) {

            atomic_long_t *watchpoint;
            long found_addr;
            watchpoint = find_write_watchpoint(var_access_info, &found_addr);
            if (watchpoint) {
                found_write_watchpoint(var_access_info, watchpoint, found_addr);
            } else {
                watchpoint = find_read_watchpoint(var_access_info, &found_addr);
                if(watchpoint){
                    found_read_watchpoint(var_access_info, watchpoint, found_addr);
                }
                else{
                    setup_write_watchpoint(var_access_info);   
                }
            }
        } else {
            return;
        }
    } else if(checking_sync_phase || random_delay_logging_phase) {
        atomic_long_t *watchpoint;
        long found_addr;
        // 用于 free - read&write 同时测试
        // watchpoint = find_free_watchpoint(var_access_info, &found_addr);
        // if (watchpoint) {
        //     found_free_watchpoint(var_access_info, watchpoint, found_addr);
        // }
        if (var_access_info.is_write){
            watchpoint = find_write_watchpoint(var_access_info, &found_addr);
            if (watchpoint) {
                found_write_watchpoint(var_access_info, watchpoint, found_addr);
            } else {
                watchpoint = find_read_watchpoint(var_access_info, &found_addr);
                if(watchpoint){
                    found_read_watchpoint(var_access_info, watchpoint, found_addr);
                }
                else{
                    setup_write_watchpoint(var_access_info);   
                }
            }
        }
        else{
            watchpoint = find_write_watchpoint(var_access_info, &found_addr);
            if (watchpoint) {
                found_write_watchpoint(var_access_info, watchpoint, found_addr);
            } else {
                setup_read_watchpoint(var_access_info);   
            }
        }

    }
    if (validating_phase){
        atomic_set(&validate_race_pair_trigger_flag,0);
    }else if(checking_sync_phase){
        atomic_set(&may_race_pair_trigger_flag,0);
    }
    
}
EXPORT_SYMBOL(rec_mem_access);