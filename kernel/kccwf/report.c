#include "report.h"
#include "linux/spinlock.h"
#include "linux/spinlock_types_raw.h"

bool check_reported(reported_info_t *reported_info, unsigned long name_1,
		    unsigned long name_2)
{
	raw_spin_lock_irqsave(&reported_info->lock, reported_info->flags);
	for (int i = 0; i < reported_info->count; i++) {
		if ((reported_info->reported_pairs[i].name_1 == name_1 &&
		     reported_info->reported_pairs[i].name_2 == name_2) ||
		    (reported_info->reported_pairs[i].name_1 == name_2 &&
		     reported_info->reported_pairs[i].name_2 == name_1)) {
			raw_spin_unlock_irqrestore(&reported_info->lock,
						   reported_info->flags);
			return true;
		}
	}
	raw_spin_unlock_irqrestore(&reported_info->lock, reported_info->flags);
	return false;
}

void push_reported(reported_info_t *reported_info, unsigned long name_1,
		   unsigned long name_2)
{
	raw_spin_lock_irqsave(&reported_info->lock, reported_info->flags);
	reported_info->reported_pairs[reported_info->count].name_1 = name_1;
	reported_info->reported_pairs[reported_info->count].name_2 = name_2;
	reported_info->count++;
	raw_spin_unlock_irqrestore(&reported_info->lock, reported_info->flags);
	return;
}

void clear_report_info(report_info_t *report_infos, int watchpoint_idx)
{
	report_infos[watchpoint_idx].num_entries = 0;
}

void set_report_info(report_info_t *report_infos, raw_spinlock_t *report_lock,
		     const volatile void *addr, int is_write,
		     int watchpoint_idx, int file_line, unsigned long var_name,
		     int tid, int cpu)
{
	unsigned long flags;
	raw_spin_lock_irqsave(report_lock, flags);
	struct task_struct *task = current;
	report_infos[watchpoint_idx].task = task;
	report_infos[watchpoint_idx].num_entries =
		stack_trace_save(report_infos[watchpoint_idx].stack_entries,
				 NUM_STACK_ENTRIES, 0);
	report_infos[watchpoint_idx].file_line = file_line;
	report_infos[watchpoint_idx].var_name = var_name;
	report_infos[watchpoint_idx].tid = tid;
	report_infos[watchpoint_idx].cpu = cpu;
	raw_spin_unlock_irqrestore(report_lock, flags);
}
// [FIX ME] 将reported也解耦
void report_race(report_info_t *report_infos, reported_info_t *reported_infos,
		 const volatile void *addr, int is_write, int watchpoint_idx,
		 unsigned long var_name, int file_line, char *report_type)
{
	struct task_struct *task = current;
	struct unwind_state state;
	unsigned long address;

	unsigned long flags;
	if (check_reported(reported_infos, var_name,
			   report_infos[watchpoint_idx].var_name)) {
		return;
	}

	printk(KERN_INFO "Kernel panic: ============ %s ============",
	       report_type);
	printk(KERN_INFO
	       "VarName %llu, BlockLineNumber %d, IrLineNumber %d, is write %d\n",
	       var_name, ((file_line >> 16) & 0xffff), (file_line & 0xffff),
	       is_write);
	for (unwind_start(&state, task, NULL, NULL); !unwind_done(&state);
	     unwind_next_frame(&state)) {
		address = unwind_get_return_address(&state);
		printk(KERN_INFO "Function: %pS\n", (void *)address);
	}
	printk(KERN_INFO "============OTHER_INFO============\n");
	printk(KERN_INFO
	       "VarName %llu, BlockLineNumber %d, IrLineNumber %d, watchpoint index %d\n",
	       report_infos[watchpoint_idx].var_name,
	       ((report_infos[watchpoint_idx].file_line >> 16) & 0xffff),
	       (report_infos[watchpoint_idx].file_line & 0xffff),
	       watchpoint_idx);
	for (int i = 0; i < report_infos[watchpoint_idx].num_entries; i++) {
		unsigned long address =
			report_infos[watchpoint_idx].stack_entries[i];
		printk(KERN_INFO "Function: %pS\n", (void *)address);
	}
	printk(KERN_INFO "=================END==============\n");

	push_reported(reported_infos, var_name,
	  report_infos[watchpoint_idx].var_name);
	return;
}
void kccwf_report_init(unsigned long *recorded_pair, int num,
		       reported_info_t *reported_info)
{
	raw_spin_lock_irqsave(&reported_info->lock, reported_info->flags);
	for (int i = 0; i < num; i++) {
		reported_info->reported_pairs[reported_info->count].name_1 =
			recorded_pair[2 * i];
		reported_info->reported_pairs[reported_info->count].name_2 =
			recorded_pair[2 * i + 1];
		reported_info->count++;
	}
	raw_spin_unlock_irqrestore(&reported_info->lock, reported_info->flags);
}

void kccwf_report_exit(void)
{
}