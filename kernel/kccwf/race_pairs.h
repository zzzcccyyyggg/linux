#ifndef _KCCWF_RACE_PAIRS_H
#define _KCCWF_RACE_PAIRS_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include "report.h"

#define KCCWF_MAX_READ_ACCESS_INFOS 512000
#define KCCWF_MAX_WRITE_ACCESS_INFOS 51200
#define KCCWF_MAX_RACE_PAIRS 0X10000
#define KCCWF_NO_SYNC_RACE_PAIRS 0X1000
#define KCCWF_RACE_PAIRS_HAS_CHECKED 0X10000

typedef struct __attribute__((aligned(64))) read_access_info {
	pid_t tid;
	unsigned long var_name;
	const volatile void *var_addr;
	unsigned long access_time;
	unsigned long sn; // Serial Number
	unsigned int size;
	int file_line;
	unsigned long stack_entries[NUM_STACK_ENTRIES];
	int num_entries;
	unsigned long stack_hash;
	bool is_alive;
} read_access_info_t;


typedef struct __attribute__((aligned(64))) write_access_info {
	pid_t tid;
	const volatile void *var_addr;
	unsigned long access_time;
	unsigned int size;
	unsigned long stack_entries[NUM_STACK_ENTRIES];
	int num_entries;
} write_access_info_t;

/* Race pair comparison function type */

/* Core race pair structure (cache-line aligned) */
typedef struct race_pair {
	unsigned long read_name;
	unsigned long sn;
	unsigned long interval_time;
	unsigned long call_stack_hash;
} __attribute__((aligned(64))) race_pair_t;

typedef bool (*race_pair_cmp_fn)(const struct race_pair *,
				 const struct race_pair *);

/* List entry that contains a race pair */
typedef struct race_pair_entry {
	struct race_pair pair;
	struct list_head list;
} race_pair_entry_t;

/* Thread-safe race pair collection */
struct race_pair_collection {
	struct list_head pairs;
	spinlock_t lock;
};

/* Main concurrent pairs container */
typedef struct concurrent_pairs {
	struct race_pair_collection may_race;
	struct race_pair_collection no_sync_race;
	struct race_pair_collection checked_race;
} concurrent_pairs_t;

/* Initialization */
void race_pairs_init(concurrent_pairs_t *pairs);

/* Core operations */
bool race_pairs_add(struct race_pair_collection *collection,
			  const struct race_pair *pair, race_pair_cmp_fn cmp);

bool race_pairs_remove(struct race_pair_collection *collection,
			     const struct race_pair *pair,
			     race_pair_cmp_fn cmp);
struct race_pair_entry *
race_pairs_find(struct race_pair_collection *collection,
		      const struct race_pair *target, race_pair_cmp_fn cmp);
void race_pairs_clear(struct race_pair_collection *collection);

/* Comparison functions */
bool race_pair_match_all(const struct race_pair *a,
			       const struct race_pair *b);
bool race_pair_match_name(const struct race_pair *a,
				const struct race_pair *b);
bool race_pair_match_name_and_stack(const struct race_pair *a,
					  const struct race_pair *b);

#endif /* _KCCWF_RACE_PAIRS_H */