#include "delay_checker.h"

static atomic_long_t watchpoints[MAX_WATCHPOINTS];

void rec_lock(char *name, int flag, int attribute, void *lock_ptr)
{
}
EXPORT_SYMBOL(rec_lock);

static __always_inline atomic_long_t *find_watchpoint(access_info_t var_access_info, long *found_addr)
{
    atomic_long_t *watchpoint;
    for (int i = 0; i < MAX_WATCHPOINTS; i++)
    {
        watchpoint = &watchpoints[i];
        *found_addr = atomic_long_read(watchpoint);

        // 比较当前找到的地址与目标地址
        if (*found_addr == (long)var_access_info.addr)
        {
            // printk(KERN_INFO "Watchpoint found at index %d: addr = %lx\n", i, *found_addr);
            return watchpoint;
        }
    }
    return NULL;
}

static inline atomic_long_t *insert_watchpoint(unsigned long addr, int is_write)
{
    atomic_long_t *watchpoint;
    // addr &= 0xfffffffffffffffe;
    // if (is_write){
    //     addr |= 1;
    // }
    for (int i = 0; i < MAX_WATCHPOINTS; i++)
    {
        long expect_val = INVALID_VALUE;
        watchpoint = &watchpoints[i];

        if (atomic_long_try_cmpxchg_relaxed(watchpoint, &expect_val, addr))
        {
            // if (is_validating_phase)
            // {
            //     printk(KERN_INFO "Watchpoint inserted at index %d: addr = %lx, is_write = %d\n", i, addr, is_write);
            // }
            return watchpoint;
        }
    }

    if (is_validating_phase)
    {
        printk(KERN_INFO "Failed to insert watchpoint for addr: %lx\n", addr);
    }

    return NULL;
}
static u8 read_instrumented_memory8(unsigned long addr)
{
    return *(volatile u8 *)(uintptr_t)addr;
}

static u16 read_instrumented_memory16(unsigned long addr)
{
    return *(volatile u16 *)(uintptr_t)addr;
}

static u32 read_instrumented_memory32(unsigned long addr)
{
    return *(volatile u32 *)(uintptr_t)addr;
}

static u64 read_instrumented_memory64(unsigned long addr)
{
    return *(volatile u64 *)(uintptr_t)addr;
}

static u64 read_instrumented_memory(unsigned long addr, int type)
{
    // printk(KERN_INFO "[rec_mem_access] 0x%016lx type is %d\n", addr, (type >> 28) & 0xf);
    switch ((type >> 28) & 0xf)
    {
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

// 将其设置为 CONSUMED_VALUE 并返回其原来的值
static long consume_watchpoint(atomic_long_t *watchpoint)
{
    return atomic_long_xchg_relaxed(watchpoint, CONSUMED_VALUE);
}

static void remove_watchpoint(atomic_long_t *watchpoint)
{
    atomic_long_set(watchpoint, INVALID_VALUE);
}

#include <linux/kernel.h> // 添加头文件以使用 printk

static void setup_watchpoint(access_info_t var_access_info)
{
    u64 old, new, diff;
    atomic_long_t *watchpoint;
    int value_change = VALUE_CHANGED_FALSE;

    // 仅在验证阶段输出
    // if (is_validating_phase)
    // {
    //     printk(KERN_INFO "Setting up watchpoint for addr: %lx, is_write: %d\n",
    //            (unsigned long)var_access_info.addr, var_access_info.is_write);
    // }

    watchpoint = insert_watchpoint((unsigned long)var_access_info.addr, var_access_info.is_write);
    if (!watchpoint)
    {
        if (is_validating_phase)
        {
            printk(KERN_ERR "Failed to insert watchpoint for addr: %lx\n", (unsigned long)var_access_info.addr);
        }
        return;
    }

    old = read_instrumented_memory(var_access_info.addr, var_access_info.type);
    set_report_info(var_access_info.addr, var_access_info.is_write, watchpoint - watchpoints, var_access_info.file_line, var_access_info.func_name);
    
    spin_lock_irqsave(&is_writes_lock, is_writes_lock_flags);
    is_writes[watchpoint - watchpoints] = var_access_info.is_write;
    spin_unlock_irqrestore(&is_writes_lock, is_writes_lock_flags);
    // if (is_validating_phase)
    // {
    //     printk(KERN_INFO "Initial value at addr %lx: %llx\n", (unsigned long)var_access_info.addr, old);
    // }
    int delay_time = var_access_info.delay_time;
    while (delay_time >= 2000)
    {
        udelay(2000);
        delay_time -= 2000;
    }

    udelay(delay_time);
    // printk("Delay time: %d microseconds\n", var_access_info.delay_time);

    new = read_instrumented_memory(var_access_info.addr, var_access_info.type);
    // if (is_validating_phase)
    // {
    //     printk(KERN_INFO "New value at addr %lx after delay: %llx\n", (unsigned long)var_access_info.addr, new);
    // }

    diff = new ^ old;
    // long state = consume_watchpoint(watchpoint);
    // if (state == CONSUMED_VALUE)
    // {
    //     // printk(KERN_INFO "Another is write %d\n", is_writes[watchpoint - watchpoints]);
    //     report_race(var_access_info.addr, var_access_info.is_write,
    //                 watchpoint - watchpoints, var_access_info.func_name,
    //                 var_access_info.file_line);
    //     spin_lock_irqsave(&is_writes_lock, is_writes_lock_flags);
    //     is_writes[watchpoint - watchpoints] = 0;
    //     spin_unlock_irqrestore(&is_writes_lock, is_writes_lock_flags);
    // }
    // else if (state == READ_VALUE && var_access_info.is_write)
    // {
    //     printk(KERN_INFO "Another is write %d\n", is_writes[watchpoint - watchpoints]);
    //     report_race(var_access_info.addr, var_access_info.is_write,
    //                 watchpoint - watchpoints, var_access_info.func_name,
    //                 var_access_info.file_line);
    // }
    // if (diff)
    // {
    //     value_change = VALUE_CHANGED_TRUE;
    //     printk(KERN_INFO "Value change detected at addr %lx: old = %llx, new = %llx, diff = %llx\n",
    //            (unsigned long)var_access_info.addr, old, new, diff);
    //     report_race(var_access_info.addr, var_access_info.is_write,
    //                 watchpoint - watchpoints, var_access_info.func_name,
    //                 var_access_info.file_line);
    // }
    spin_lock_irqsave(&is_writes_lock, is_writes_lock_flags);
    is_writes[watchpoint - watchpoints] = 0;
    spin_unlock_irqrestore(&is_writes_lock, is_writes_lock_flags);
    remove_watchpoint(watchpoint);
}

static bool try_consume_watchpoint(atomic_long_t *watchpoint, long found_addr)
{
    return atomic_long_try_cmpxchg_relaxed(watchpoint, &found_addr, CONSUMED_VALUE);
}
static bool try_consume_watchpoint_with_read(atomic_long_t *watchpoint, long found_addr)
{
    return atomic_long_try_cmpxchg_relaxed(watchpoint, &found_addr, READ_VALUE);
}
static bool try_consume_watchpoint_with_write(atomic_long_t *watchpoint, long found_addr)
{
    return atomic_long_try_cmpxchg_relaxed(watchpoint, &found_addr, WRITE_VALUE);
}

static void found_watchpoint(access_info_t var_access_info, atomic_long_t *watchpoint, long found_addr)
{
    // printk(KERN_INFO "Hello world!\n");
    bool consumed = 0;
    // printk(KERN_INFO "Watchpoint found at index %d: addr = %lx\n", i, *found_addr);
    if (var_access_info.is_write)
    {
        printk(KERN_INFO "found addr %lx is_write = %d\n", found_addr, var_access_info.is_write);
        // consumed = try_consume_watchpoint(watchpoint, found_addr);
        report_race(var_access_info.addr, var_access_info.is_write,
                    watchpoint - watchpoints, var_access_info.func_name,
                    var_access_info.file_line);
    }
    else
    {
        if (is_writes[watchpoint - watchpoints])
        {
            printk(KERN_INFO "watch point idx %d is_write = %d\n", (watchpoint - watchpoints), is_writes[watchpoint - watchpoints]);
            report_race(var_access_info.addr, var_access_info.is_write,
                        watchpoint - watchpoints, var_access_info.func_name,
                        var_access_info.file_line);
            // consumed = try_consume_watchpoint(watchpoint, found_addr);
        }
    }
    // if (consumed)
    // {

    //     // // printk(KERN_INFO "Hello world!\n");

    //     // printk(KERN_INFO "found watchpoint over,addr is %lu\n",found_addr);
    // }
}

static inline bool is_heap_memory(unsigned long addr)
{
    void *ptr = (void *)(uintptr_t)addr; // 将地址转换为指针

    // 检查是否是 vmalloc 分配的内存
    if (is_vmalloc_addr(ptr))
        return true;

    // 检查是否是有效的内核地址，通常适用于 kmalloc 分配的内存
    if (virt_addr_valid(ptr))
        return true;

    return false;
}

static void log_access_info(const access_info_t *var_access_info)
{

    // //* 添加的call stack逻辑
    // unsigned long func_name = var_access_info->func_name;
    // spin_lock_irqsave(&thread_chain_lock, thread_chain_lock_flags);
    // thread_chain_t *tc;
    // list_for_each_entry(tc, &global_thread_chain_head, list) {
    //     if (tc->tid == var_access_info->tid) {
    //         func_name += tc->thread_call_stack_hash;
    //     }
    // }
    // printk(KERN_INFO "rec_mem_access: log hash %lu\n", var_access_info->func_name);
    // spin_unlock_irqrestore(&thread_chain_lock, thread_chain_lock_flags);
    trace_printk("Access info: addr %lu, is_write %d, func_name %lu, file_line %d, type %d, access_time %lu, tid %d, access_count %lu, delay_time %d\n",
                 var_access_info->addr, var_access_info->is_write, var_access_info->func_name, var_access_info->file_line, var_access_info->type, var_access_info->access_time, var_access_info->tid, var_access_info->access_count,
                 var_access_info->delay_time);
}

static void set_access_info(access_info_t *var_access_info, unsigned long addr, int is_write, unsigned long func_name, int file_line, int type, unsigned long access_time, pid_t tid)
{
    var_access_info->addr = addr;
    var_access_info->is_write = is_write;
    var_access_info->func_name = func_name;
    var_access_info->file_line = file_line;
    var_access_info->type = type;
    var_access_info->access_time = access_time;
    var_access_info->tid = tid;
    var_access_info->access_count = 1;
    var_access_info->delay_time = 80;
    var_access_info->next_idx = -1;
}
static void init_access_info(int i)
{
    access_infos[i].addr = 0;
    access_infos[i].is_write = 0;
    access_infos[i].func_name = -1;
    access_infos[i].file_line = -1;
    access_infos[i].type = -1;
    access_infos[i].access_time = 0;
    access_infos[i].tid = -1;
    access_infos[i].access_count = 0;
    access_infos[i].delay_time = 80;
    access_infos[i].is_skip = 0;
    access_infos[i].next_idx = -1;
}
// visited[i] 用于检测是否存在环路
void clear_visited(void)
{
    for (int i = 0; i < MAX_ACCESS_INFOS; i++)
    {
        visited[i] = false;
    }
}
int insert_hash_table(unsigned long addr, int is_write, unsigned long func_name, int file_line, int type, unsigned long access_time, pid_t tid)
{

    spin_lock_irqsave(&access_info_lock, access_info_lock_flags);
    clear_visited();
    int index = func_name % MAX_ACCESS_INFOS;

    // 如果索引位置为空，则直接插入
    if (access_infos[index].func_name == -1)
    {
        access_infos[index].addr = addr;
        access_infos[index].is_write = is_write;
        access_infos[index].func_name = func_name;
        access_infos[index].file_line = file_line;
        access_infos[index].type = type;
        access_infos[index].access_time = access_time;
        access_infos[index].tid = tid;
        access_infos[index].access_count = 1;
        access_infos[index].delay_time = 80;
        access_infos[index].is_skip = 0;
        access_infos[index].next_idx = -1;
    }
    else
    {
        // 如果索引位置不为空，遍历链表找到插入位置
        int temp_idx = index;

        while (access_infos[temp_idx].next_idx != -1)
        {
            // 如果当前索引已访问过，则检测到循环
            if (visited[temp_idx])
            {
                pr_err("Detected potential infinite loop in access_infos.\n");
                spin_unlock_irqrestore(&access_info_lock, access_info_lock_flags);
                return -1;
            }

            visited[temp_idx] = 1; // 标记当前索引为已访问
            temp_idx = access_infos[temp_idx].next_idx;
        }

        // 查找下一个可用的空位
        int temp = (temp_idx + 1) % MAX_ACCESS_INFOS;

        while (access_infos[temp].func_name != -1)
        {
            // 如果当前索引已访问过，则检测到循环
            if (visited[temp])
            {
                pr_err("Detected potential infinite loop during insertion.\n");
                spin_unlock_irqrestore(&access_info_lock, access_info_lock_flags);
                return -1;
            }

            visited[temp] = 1; // 标记当前索引为已访问
            temp = (temp + 1) % MAX_ACCESS_INFOS;

            // 如果哈希表已满，返回失败
            if (temp == index)
            {
                pr_err("Hash table is full, cannot insert new entry.\n");
                spin_unlock_irqrestore(&access_info_lock, access_info_lock_flags);
                return -1;
            }
        }

        // 插入新条目
        access_infos[temp].addr = addr;
        access_infos[temp].is_write = is_write;
        access_infos[temp].func_name = func_name;
        access_infos[temp].file_line = file_line;
        access_infos[temp].type = type;
        access_infos[temp].access_time = access_time;
        access_infos[temp].tid = tid;
        access_infos[temp].access_count = 1;
        access_infos[temp].delay_time = 80;
        access_infos[temp].is_skip = 0;
        access_infos[temp].next_idx = -1;

        // 更新链表指针
        access_infos[temp_idx].next_idx = temp;
    }

    spin_unlock_irqrestore(&access_info_lock, access_info_lock_flags);
    return 0;
}

// 查找哈希表 并返回delay_time(若查找到)
int search_hash_table(unsigned long func_name)
{
    clear_visited(); // 清除访问记录

    int index = func_name % MAX_ACCESS_INFOS;
    while (access_infos[index].func_name != func_name)
    {
        if (access_infos[index].next_idx == -1 || visited[index])
        {
            return -1;
        }
        visited[index] = true; // 标记当前索引已访问
        index = access_infos[index].next_idx;
    }

    if (access_infos[index].is_skip)
    {
        return 0;
    }
    int delay_time = access_infos[index].delay_time;
    return delay_time;
}
// 删除哈希表中某个特定元素
int remove_hash_table(unsigned long func_name)
{
    spin_lock_irqsave(&access_info_lock, access_info_lock_flags);
    clear_visited();

    int index = func_name % MAX_ACCESS_INFOS;
    int previous_index = -1;

    while (access_infos[index].func_name != func_name)
    {
        if (access_infos[index].next_idx == -1 || visited[index])
        {
            spin_unlock_irqrestore(&access_info_lock, access_info_lock_flags);
            return -1; // 找不到或检测到环
        }
        visited[index] = true;
        previous_index = index;
        index = access_infos[index].next_idx;
    }

    if (previous_index != -1)
    {
        access_infos[previous_index].next_idx = access_infos[index].next_idx;
    }
    init_access_info(index);
    spin_unlock_irqrestore(&access_info_lock, access_info_lock_flags);
    return 0; // 成功删除
}
void rec_mem_access(unsigned long addr, unsigned long func_name, int is_write, int file_line, int type)
{
    // 检查地址是否为堆内存
    // if (!is_heap_memory(addr))
    // {
    //     printk(KERN_INFO "rec_mem_access: Address %lu is not heap memory, skipping.\n", addr);
    //     return;
    // }

    atomic_long_t *watchpoint;
    long found_addr;

    // 获取访问时间和线程ID
    ktime_t access_time = ktime_get();
    pid_t tid = get_thread_id();

    //* 添加的call stack逻辑
    spin_lock_irqsave(&thread_chain_lock, thread_chain_lock_flags);
    thread_chain_t *tc;
    list_for_each_entry(tc, &global_thread_chain_head, list)
    {
        if (tc->tid == tid)
        {
            func_name += 0;
        }
    }
    spin_unlock_irqrestore(&thread_chain_lock, thread_chain_lock_flags);

    // 加锁并查询延迟时间
    spin_lock_irqsave(&access_info_lock, access_info_lock_flags);
    int delay_time = search_hash_table(func_name);
    spin_unlock_irqrestore(&access_info_lock, access_info_lock_flags);
    // 如果没有找到延迟时间，使用默认值
    if (delay_time == -1)
    {
        if (is_validating_phase)
        {
            return;
        }
        else
        {
            if (is_random_delay_phase)
            {
                delay_time = get_random_u32_below(1000);
            }
            else
            {
                delay_time = 0;
            }
        }
    }
    // if (get_random_u32_below(100) > 50){
    //     delay_time = 0;
    // }
    // 初始化变量访问信息

    access_info_t var_access_info = {
        .addr = addr,
        .is_write = is_write,
        .func_name = func_name,
        .file_line = file_line,
        .type = type,
        .access_time = access_time,
        .tid = tid,
        .access_count = 1,
        .delay_time = delay_time,
        .is_skip = 0,
        .next_idx = -1};
    // printk(KERN_INFO "rec_mem_access: hash %lu\n", func_name);
    // 记录访问信息
    log_access_info(&var_access_info);

    // 尝试找到已有的监视点
    watchpoint = find_watchpoint(var_access_info, &found_addr);

    if (watchpoint)
    {
        found_watchpoint(var_access_info, watchpoint, found_addr);
    }
    else
    {
        setup_watchpoint(var_access_info);
    }
}

EXPORT_SYMBOL(rec_mem_access);