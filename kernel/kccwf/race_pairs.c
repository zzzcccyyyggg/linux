#include "race_pairs.h"
#include "linux/kccwf.h"
#include <linux/slab.h>
#include <linux/preempt.h>

/* Initialize a race pair collection */
static void race_pair_collection_init(struct race_pair_collection *collection)
{
	INIT_LIST_HEAD(&collection->pairs);
	spin_lock_init(&collection->lock);
}

void race_pairs_init(struct concurrent_pairs *pairs)
{
	race_pair_collection_init(&pairs->may_race);
	race_pair_collection_init(&pairs->no_sync_race);
	race_pair_collection_init(&pairs->checked_race);
}

/* Thread-safe add operation */
bool race_pairs_add(struct race_pair_collection *collection,
			  const struct race_pair *pair, race_pair_cmp_fn cmp)
{
	struct race_pair_entry *entry;
	unsigned long flags;
	bool duplicate = false;

	/* Check for duplicates first */
	spin_lock_irqsave(&collection->lock, flags);
	list_for_each_entry(entry, &collection->pairs, list) {
		if (cmp(&entry->pair, pair)) {
			duplicate = true;
			break;
		}
	}

	/* Only add if not a duplicate */
	if (!duplicate) {
		entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
		if (entry) {
			entry->pair = *pair;
			list_add_tail(&entry->list, &collection->pairs);
		} else {
			duplicate =
				true; /* Treat allocation failure as duplicate */
		}
	}
	spin_unlock_irqrestore(&collection->lock, flags);

	return !duplicate;
}

/* Thread-safe find operation */
struct race_pair_entry *
race_pairs_find(struct race_pair_collection *collection,
		      const struct race_pair *target, race_pair_cmp_fn cmp)
{
	struct race_pair_entry *entry;
	unsigned long flags;

	spin_lock_irqsave(&collection->lock, flags);
	list_for_each_entry(entry, &collection->pairs, list) {
		if (cmp(&entry->pair, target)) {
			spin_unlock_irqrestore(&collection->lock, flags);
			return entry;
		}
	}
	spin_unlock_irqrestore(&collection->lock, flags);
	return NULL;
}

/* Thread-safe remove operation */
bool race_pairs_remove(struct race_pair_collection *collection,
			     const struct race_pair *target,
			     race_pair_cmp_fn cmp)
{
	struct race_pair_entry *entry, *tmp;
	unsigned long flags;
	bool removed = false;
	spin_lock_irqsave(&collection->lock, flags);
	list_for_each_entry_safe(entry, tmp, &collection->pairs, list) {
		if (cmp(&entry->pair, target)) {
			list_del(&entry->list);
			kccwf_disable();
			kfree(entry);
			kccwf_enable();
			removed = true;
			break;
		}
	}
	spin_unlock_irqrestore(&collection->lock, flags);
	return removed;
}

void race_pairs_clear(struct race_pair_collection *collection)
{
	struct race_pair_entry *entry, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&collection->lock, flags);
	list_for_each_entry_safe(entry, tmp, &collection->pairs, list) {
		list_del(&entry->list);
		kccwf_disable();
		kfree(entry);
		kccwf_enable();
	}
	spin_unlock_irqrestore(&collection->lock, flags);
}

/* Comparison functions */
bool race_pair_match_all(const struct race_pair *a,
			       const struct race_pair *b)
{
	return a->read_name == b->read_name && a->sn == b->sn &&
	       a->call_stack_hash == b->call_stack_hash;
}

bool race_pair_match_name(const struct race_pair *a,
				const struct race_pair *b)
{
	return a->read_name == b->read_name;
}

bool race_pair_match_name_and_stack(const struct race_pair *a,
					  const struct race_pair *b)
{
	return a->read_name == b->read_name &&
	       a->call_stack_hash == b->call_stack_hash;
}