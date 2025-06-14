#ifndef KCCWF_ENCODING_H
#define KCCWF_ENCODING_H

#include <linux/bits.h>
#include <linux/log2.h>
#include <linux/mm.h>
#include <linux/kccwf.h>

#define KCCWF_NUM_WATCHPOINTS 40960
#define KCCWF_CHECK_ADJACENT 15
#define NUM_SLOTS (1 + 2*KCCWF_CHECK_ADJACENT)
#define SLOT_IDX(slot, i) (slot + ((i + KCCWF_CHECK_ADJACENT) % NUM_SLOTS))
#define SLOT_IDX_FAST(slot, i) (slot + i)
#define REAL_NUM_WATCHPOINTS (KCCWF_NUM_WATCHPOINTS + NUM_SLOTS - 1)

// [FIX ME] replace with a hash function that can be more efficient and able to avoid hash collisions
static __always_inline int watchpoint_slot(unsigned long addr) {
    const unsigned long A = 2654435761U; // 黄金比例素数 (2^32 / φ)
    return (addr * A) % KCCWF_NUM_WATCHPOINTS;
}

// 调整宏定义：移除 is_write 相关掩码，地址掩码扩展至 48 位
#define WATCHPOINT_SIZE_BITS   16
#define MAX_ENCODABLE_SIZE     0xFFFF
#define WATCHPOINT_SIZE_MASK   GENMASK(BITS_PER_LONG-1, BITS_PER_LONG - WATCHPOINT_SIZE_BITS) // 0xFFFF000000000000

// 地址占据低 48 位
#define WATCHPOINT_ADDR_MASK   GENMASK(BITS_PER_LONG - WATCHPOINT_SIZE_BITS - 1, 0) // 0x0000FFFFFFFFFFFF (48位)

static inline bool check_encodable(unsigned long addr, size_t size)
{
    // 地址需满足：
    // 1. 不小于 PAGE_SIZE（避免空指针解引用）
    // 2. 不超过 48 位地址掩码范围
    const bool is_addr_valid = addr >= PAGE_SIZE && 
                              (addr & WATCHPOINT_ADDR_MASK) == addr;

    // 检查 size 是否在 16 位范围内
    const bool is_size_valid = size <= MAX_ENCODABLE_SIZE;

    return is_addr_valid && is_size_valid;
}

static inline long
encode_watchpoint(unsigned long addr, size_t size)
{
    return (long)(
        (((size & MAX_ENCODABLE_SIZE) << (BITS_PER_LONG - WATCHPOINT_SIZE_BITS)) |  // size 左移到高16位
        (addr & WATCHPOINT_ADDR_MASK))                     // 地址保留低48位
    );
}

/* 解码函数 */
static __always_inline bool
decode_watchpoint(long watchpoint, unsigned long *addr, size_t *size)
{
    *size = ((unsigned long)watchpoint & WATCHPOINT_SIZE_MASK) >> (BITS_PER_LONG - WATCHPOINT_SIZE_BITS);
    *addr = (unsigned long)watchpoint & WATCHPOINT_ADDR_MASK;
    return true;
}

static __always_inline bool matching_access(unsigned long addr1, size_t size1,
                                            unsigned long addr2, size_t size2)
{
    unsigned long end_range1 = addr1 + size1 - 1;
    unsigned long end_range2 = addr2 + size2 - 1;

    return addr1 <= end_range2 && addr2 <= end_range1;
}

#endif /* KCCWF_ENCODING_H */