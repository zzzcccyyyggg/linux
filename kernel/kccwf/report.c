#include "report.h"

bool check_reported(unsigned long name_1, int line_1, unsigned long name_2, int line_2) {
    unsigned long flags;
    raw_spin_lock_irqsave(&reported_lock, flags);
    for (int i = 0; i < MAX_WATCHPOINTS; i++) {
        if (((reported_funcs[i].name_1 == name_1 && reported_funcs[i].line_1 == line_1) && (reported_funcs[i].name_2 == name_2 && reported_funcs[i].line_2 == line_2)) \
              || ((reported_funcs[i].name_1 == name_2 && reported_funcs[i].line_1 == line_2) && (reported_funcs[i].name_2 == name_1 && reported_funcs[i].line_2 == line_1))) {
            raw_spin_unlock_irqrestore(&reported_lock, flags);
            return true;
        }
    }
    raw_spin_unlock_irqrestore(&reported_lock, flags);
    return false;
}

void push_reported(unsigned long name_1, int line_1, unsigned long name_2, int line_2) {
    unsigned long flags;
    raw_spin_lock_irqsave(&reported_lock, flags);
    for (int i = 0; i < MAX_WATCHPOINTS; i++) {
        if (reported_funcs[i].name_1 == 0) {
            reported_funcs[i].name_1 = name_1;
            reported_funcs[i].line_1 = line_1;
            reported_funcs[i].line_2 = line_2;
            reported_funcs[i].name_2 = name_2;
            raw_spin_unlock_irqrestore(&reported_lock, flags);
            return;
        }
    }
    raw_spin_unlock_irqrestore(&reported_lock, flags);
    return;
}

DEFINE_SET_REPORT_INFO_FUNCTION(write, write_report_infos)
DEFINE_SET_REPORT_INFO_FUNCTION(read, read_report_infos)

DEFINE_REPORT_RACE_FUNCTION(read, read_report_infos,"===========================UAF===========================\n")
DEFINE_REPORT_RACE_FUNCTION(write, write_report_infos,"===========================DOUBLE FREE===========================\n")

void clear_read_report_info(int watchpoint_idx){
    read_report_infos[watchpoint_idx].num_entries = 0;
}
void clear_write_report_info(int watchpoint_idx){
    write_report_infos[watchpoint_idx].num_entries = 0;
}