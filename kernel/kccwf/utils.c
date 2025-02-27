#include "utils.h"

int get_thread_id(void) {
    int i = 0;
    int pid = current->pid;
    char *comm = current->comm;

    if (pid == 0) {
        name_list_t *name_node;
        spin_lock_irqsave(&pid_0_name_list_lock, pid_0_name_list_lock_flags);
        list_for_each_entry(name_node, &pid_0_name_list, list) {
            if (strcmp(name_node->name, comm) == 0) {
                spin_unlock_irqrestore(&pid_0_name_list_lock, pid_0_name_list_lock_flags);
                return PID_MAX_DEFAULT + i;
            }
            i++;
        }
        name_node = (name_list_t *)kzalloc(sizeof(name_list_t), GFP_ATOMIC);
        if (!name_node) {
            printk(KERN_WARNING "[KERNEL_MONITOR] kernel_monitor: can't allocate memory\n");
            spin_unlock_irqrestore(&pid_0_name_list_lock, pid_0_name_list_lock_flags);
            return -ENOMEM;
        }
        name_node->name = comm;
        list_add_tail(&name_node->list, &pid_0_name_list);
        spin_unlock_irqrestore(&pid_0_name_list_lock, pid_0_name_list_lock_flags);

        pid = PID_MAX_DEFAULT + i;
    }
    return pid;
}