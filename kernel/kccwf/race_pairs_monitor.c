#include "race_pairs_monitor.h"
#include "linux/atomic/atomic-instrumented.h"
#include "linux/kccwf.h"
#include "linux/printk.h"
#include "linux/spinlock.h"
#include "linux/stddef.h"

static void process_potential_race(read_access_info_t *rec,
				   write_access_info_t *write,
				   concurrent_pairs_t *concurrent_pairs)
{
	race_pair_t *may_race_pair = kmalloc(sizeof(race_pair_t), GFP_KERNEL);
	if (!may_race_pair)
		return;

	may_race_pair->interval_time = write->access_time - rec->access_time;
	may_race_pair->read_name = rec->var_name;
	may_race_pair->sn = rec->sn;

	pr_info("[KCCWF_LOG_MODE] The read access var_name is %lu, "
		"addr is %lx, size is %d, the write addr is %lx, "
		"the write size is %d, the interval_time is %lu, "
		"the sn is %lu, line num is %d, block num is %d\n",
		rec->var_name, rec->var_addr, rec->size, write->var_addr,
		write->size, may_race_pair->interval_time, may_race_pair->sn,
		((rec->file_line >> 16) & 0xffff), (rec->file_line & 0xffff));

	pr_info("stack hash is %llu\n", rec->stack_hash);

	if (race_pairs_add(&concurrent_pairs->may_race, may_race_pair,
				 race_pair_match_all)) {
		pr_info("===============================Free=======================================\n");
		pr_info("tid is %d\n", write->tid);
		stack_trace_print(write->stack_entries, write->num_entries, 0);
		pr_info("===============================USE=======================================\n");
		pr_info("tid is %d\n", rec->tid);
		stack_trace_print(rec->stack_entries, rec->num_entries, 0);
	}
}

void process_write_access(race_pairs_monitor_t *rp_monitor,
			  write_access_info_t *write_access_info,
			  concurrent_pairs_t *concurrent_pairs)
{
	unsigned long flags;
	unsigned long write_time = write_access_info->access_time;
	const unsigned long time_threshold = write_time - KCCWF_TIME_WINDOW;
	spin_lock_irqsave(&rp_monitor->read_rb.consume_lock,
			  rp_monitor->read_rb.consume_lock_flags);

	unsigned long current_head =
		raw_atomic_long_read(&rp_monitor->read_rb.head);
	unsigned long current_tail =
		raw_atomic_long_read(&rp_monitor->read_rb.tail);

	if (current_head <= current_tail) {
		spin_unlock_irqrestore(&rp_monitor->read_rb.consume_lock,
				       rp_monitor->read_rb.consume_lock_flags);
		return;
	}
	pr_info("current_head is %lu,current tail is %lu\n", current_head, current_tail);
	unsigned long valid_start = current_tail;
	unsigned long pos = current_tail;
	while (pos != current_head) {
		read_access_info_t *rec =
			&rp_monitor->read_rb
				 .buffer[pos % rp_monitor->read_rb.size];
		if (rec->access_time >= time_threshold) {
			if (rec->access_time >= write_time) {
				valid_start = pos-1;
				goto exit;
			} else {
				break;
			}
		}
		pos++;
	}
	valid_start = pos;
	// Phase 2: Batch processing of valid records
	while (pos != current_head) {
		read_access_info_t *rec =
			&rp_monitor->read_rb
				 .buffer[pos % rp_monitor->read_rb.size];
		if (rec->access_time > write_time)
			break;
		/* [Finish me]: Add the pair to the may_race_pairs */
		if (matching_access((unsigned long)rec->var_addr, rec->size,
				    (unsigned long)write_access_info->var_addr,
				    write_access_info->size)) {
			if (rec->access_time > time_threshold &&
			    rec->tid != write_access_info->tid &&
			    rec->is_alive) {
				if (kccwf_current.kccwf_mode ==
				    KCCWF_LOG_MODE) {
					process_potential_race(
						rec, write_access_info,
						concurrent_pairs);
				}
			}
		}
		pos++;
	}
exit:
	raw_atomic_long_set(&rp_monitor->read_rb.tail, (long)valid_start);
	pr_info("pos is %lu,current tail is %lu\n", current_head, pos);
	spin_unlock_irqrestore(&rp_monitor->read_rb.consume_lock,
			       rp_monitor->read_rb.consume_lock_flags);
}

/*
* Log a read access into the ring buffer
 * @param read_access Pointer to read access information
 * @return 0 on success, negative error code on failure
 */
 unsigned long log_read_access(race_pairs_monitor_t *rp_monitor,
		    read_access_info_t *read_access)
{
	unsigned long pos;
	read_access_info_t *record;
	pos = ring_buffer_produce(&rp_monitor->read_rb);
	record = (read_access_info_t *)&rp_monitor->read_rb.buffer[pos];

	record->access_time = read_access->access_time;
	record->tid = read_access->tid;
	record->var_addr = read_access->var_addr;
	record->var_name = read_access->var_name;
	record->size = read_access->size;
	record->file_line = read_access->file_line;
	record->is_alive = 1;
	record->num_entries =
		stack_trace_save(record->stack_entries, NUM_STACK_ENTRIES, 2);
	record->stack_hash = kccwf_calc_stack_hash(record->stack_entries,
						   record->num_entries);
	record->sn = kccwf_fetch_inc_access_by_hash(read_access->var_name,
						    record->stack_hash);
	// pr_info("The read access var_name is %lu, addr is %lx, size is %d\n",
	// 	read_access->var_name, read_access->var_addr,
	// 	read_access->size);
	smp_wmb();
	if (pos >= 0){
		return pos;
	}
	return 0;
}

/*
 * race_pairs_monitor_init - Initialize race pairs monitor structure
 * @rp_monitor: Pointer to the monitor structure to initialize
 *
 * Returns 0 on success, negative error code on failure.
 */
int race_pairs_monitor_init(race_pairs_monitor_t *rp_monitor,
			    concurrent_pairs_t *concurrent_pairs)
{
    int ret = 0;
    
    if (!rp_monitor) {
        return -EINVAL;
    }
	atomic_set(&rp_monitor->rp_thread_initialized, 0);

	rp_monitor->read_rb.buffer = vmalloc(sizeof(read_access_info_t)*KCCWF_RING_BUFFER_SIZE);
    ring_buffer_init(&rp_monitor->read_rb,KCCWF_RING_BUFFER_SIZE);
    if (!rp_monitor->read_rb.buffer) {
        pr_err("Failed to allocate read ring buffer\n");
        ret = -ENOMEM;
        goto err_out;
    }

	rp_monitor->write_rb.buffer = vmalloc(sizeof(write_access_info_t)*KCCWF_RING_BUFFER_SIZE);
	ring_buffer_init(&rp_monitor->write_rb,KCCWF_RING_BUFFER_SIZE);
    if (!rp_monitor->write_rb.buffer) {
        pr_err("Failed to allocate write ring buffer\n");
        ret = -ENOMEM;
        goto err_clean_read_rb;
    }
    // Initialize wait queue
    init_waitqueue_head(&rp_monitor->wq);
	rp_monitor->thread_running = false;

    return 0;
err_clean_read_rb:
	vfree(rp_monitor->read_rb.buffer);
err_out:
    return ret;
}

/*
* race_pairs_monitor_clean - Clean up race pairs monitor resources
 * @rp_monitor: Pointer to the monitor structure to clean up
 */
void race_pairs_monitor_clean(race_pairs_monitor_t *rp_monitor)
{
    if (!rp_monitor) {
        return;
    }
	// [FIX ME!]: 这里或许需要保护 thread_running
    if (rp_monitor->thread_running && rp_monitor->handler_thread) {
        rp_monitor->thread_running = false;
        wake_up(&rp_monitor->wq);
        kthread_stop(rp_monitor->handler_thread);
    }

    kfree(rp_monitor->read_rb.buffer);
    kfree(rp_monitor->write_rb.buffer);

    // Clear wait queue (no resources to free)
}
