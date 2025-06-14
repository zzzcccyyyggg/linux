#include "core.h"
#include "encoding.h"
#include "linux/kccwf.h"
#include "linux/kernel.h"
#include "linux/printk.h"
#include "report.h"
#include "wp_checker.h"

/* global variable */
kccwf_statistical_var_t kccwf_statistical_var;
kccwf_current_t kccwf_current;

/* static global variable */
static atomic_long_t read_watchpoints[REAL_NUM_WATCHPOINTS];
static atomic_long_t write_watchpoints[REAL_NUM_WATCHPOINTS];

static report_info_t read_report_infos[REAL_NUM_WATCHPOINTS];
static DEFINE_RAW_SPINLOCK(read_report_lock);

static report_info_t write_report_infos[REAL_NUM_WATCHPOINTS];
static DEFINE_RAW_SPINLOCK(write_report_lock);

static reported_info_t reported_info;

struct concurrent_pairs concurrent_pairs;

static race_pairs_monitor_t rp_monitor;

void kccwf_disable(void)
{
	current->kccwf_disable_count++;
}

void kccwf_enable(void)
{
	current->kccwf_disable_count--;
}
unsigned long recorded_pairs[] = {352112967803423825ULL,13303371432858598081ULL,419381500484574012ULL,5534898108940928201ULL,419381500484574012ULL,8619684886095753813ULL,931404231151619434ULL,6866027485044696020ULL,1653844129745408822ULL,1653849070563752446ULL,1735759313664345199ULL,3273029333701405646ULL,1735759313664345199ULL,8834491779071170131ULL,3078558288405412100ULL,15196514971298365129ULL,3078558403242414372ULL,3413986582740441945ULL,3673799242239102629ULL,4043128201441913327ULL,3673799242239102629ULL,4043153393268665504ULL,3673799242239102629ULL,5227586122710477554ULL,4491714011551644535ULL,16390737365325382077ULL,4491714011551644535ULL,17978964664826311431ULL,5534898108940928201ULL,15473204403585998307ULL,5542739135621778556ULL,7755756609592241347ULL,5542739250186777668ULL,7755756688522750018ULL,5542739443682269358ULL,13000227319808619543ULL,6021741783095319349ULL,9497716191417059795ULL,8619684886095753813ULL,13166050889201667602ULL,8619684886095753813ULL,15473204403585998307ULL,10111811113662232261ULL,15196514971298365129ULL,10199970279943428345ULL,10199970471658501518ULL,10518722952560949855ULL,16390737365325382077ULL,10518722952560949855ULL,17978964664826311431ULL,13000227319808619543ULL,17363501701721901078ULL,352112967803423825ULL,13303371432858598081ULL,419381500484574012ULL,5534898108940928201ULL,419381500484574012ULL,8619684886095753813ULL,735920047962076369ULL,17145708964271603100ULL,802724818421310327ULL,7831086080386176196ULL,931404231151619434ULL,6866027485044696020ULL,1653844129745408822ULL,1653849070563752446ULL,1735759313664345199ULL,3273029333701405646ULL,1735759313664345199ULL,8834491779071170131ULL,1850637658024622061ULL,5542739404217015083ULL,3078558288405412100ULL,15196514971298365129ULL,3078558403242414372ULL,3413986582740441945ULL,3413986582740441945ULL,10111815860710972852ULL,3459448041208659229ULL,12410830585241887385ULL,3673799242239102629ULL,4043128201441913327ULL,3673799242239102629ULL,4043153393268665504ULL,3673799242239102629ULL,5227586122710477554ULL,3673799242239102629ULL,17363506911135465378ULL,4004159437612518750ULL,16390737365325382077ULL,4004159437612518750ULL,17978964664826311431ULL,4491714011551644535ULL,16390737365325382077ULL,4491714011551644535ULL,17978964664826311431ULL,5519440494915694594ULL,5542723973304654309ULL,5534898108940928201ULL,15473204403585998307ULL,5542739135621778556ULL,7755756609592241347ULL,5542739250186777668ULL,7755756688522750018ULL,5542739404217015083ULL,5589076102123148543ULL,5542739443682269358ULL,13000227319808619543ULL,5542739443682269358ULL,16100634012471765034ULL,5864808236160097127ULL,10199970471658501518ULL,6021741783095319349ULL,9497716191417059795ULL,6953781362345233885ULL,11678488676604900513ULL,8619684886095753813ULL,13166050889201667602ULL,8619684886095753813ULL,15473204403585998307ULL,10111811113662232261ULL,15196514971298365129ULL,10199970279943428345ULL,10199970471658501518ULL,10518722952560949855ULL,16390737365325382077ULL,10518722952560949855ULL,17978964664826311431ULL,13000227319808619543ULL,17363501701721901078ULL,71219191308151079ULL,12794330810717741777ULL,5519440494915694594ULL,5864808236160097127ULL,5519440494915694594ULL,16162392819542805024ULL,11677156321928635609ULL,17978964664826311431ULL,16100634012471765034ULL,17363501701721901078ULL};
unsigned long recorded_pairs_gfs2[] = {3130800123211853559ULL,4306406048381367280ULL,615664728706652185ULL,9341060648636596934ULL,3082820861160809128ULL,3082825683581313325ULL,4306406048381367280ULL,4306406048381367280ULL,5412665992613638915ULL,5412665992613638915ULL,5412666071544147465ULL,5412666071544147465ULL,5412666186381149737ULL,5412666186381149737ULL,6414759801907023910ULL,13702095038807427950ULL,7403353687908330296ULL,7403353687908330296ULL,8082960391578836292ULL,8082960391578836292ULL,8082965446690144166ULL,8082965446690144166ULL,8082970308575902759ULL,8082970308575902759ULL,8082975284754625481ULL,8082975284754625481ULL,8082980261207443695ULL,8082980261207443695ULL,8082980375772442686ULL,8082980375772442686ULL,8082980569539953508ULL,8082980569539953508ULL,9146439196027014980ULL,9195862133150640473ULL,9195862133150640473ULL,13731726460750459918ULL};
unsigned long recorded_pairs_btrfs[] = {311359038016674014ULL,7774127420074133817ULL,2038588415464588323ULL,17976959497295600820ULL,2564976217690013587ULL,15617243991665299719ULL,7501239125788611807ULL,13790613225000599766ULL,7774127420074133817ULL,18344039467792963940ULL,8419654169773141577ULL,17097347185439352068ULL,9813326128116715780ULL,16717084515480673678ULL,9813326128116715780ULL,17405777135440161303ULL,13007338482834870954ULL,13007338482834870954ULL,15617243991665299719ULL,16717084515480673678ULL,15617243991665299719ULL,17405777135440161303ULL,17097347185439352068ULL,18013998891961692463ULL};
unsigned long recorded_pairs_jfs[] = {5598326678566478135ULL,13957078730376629373ULL,5598326678566478135ULL,13957103884788488443ULL,5598356809431155298ULL,5598356809431155298ULL,6498606766995851459ULL,6499268868181420128ULL,12072576510715726135ULL,13466627116265290337ULL,13466637187564597379ULL,18292285673101669289ULL,13957078615809569752ULL,13957083513059876256ULL,13957078730376629373ULL,13957078730376629373ULL,13957103805857995623ULL,13957103999353471583ULL};
unsigned long recorded_pairs_f2fs[] = {326423100471703638ULL,7609738934013775385ULL,1871849656170464454ULL,7673971598074960276ULL,1871849656170464454ULL,7675957823933400996ULL,1871854403219205045ULL,7673981859039011146ULL,1871854403219205045ULL,7675957938498399987ULL,1871854403219205045ULL,8035850785816011201ULL,1871854632351263657ULL,1871854632351263657ULL,1871854632351263657ULL,5961139784487988934ULL,1871854632351263657ULL,6038363033977787146ULL,1871854632351263657ULL,7673981859039011146ULL,1871854632351263657ULL,13673158195469564652ULL,1871854632351263657ULL,14260316634768525029ULL,1871854632351263657ULL,17827671482396297765ULL,1871854672088537064ULL,5961139823953243209ULL,1871854672088537064ULL,6038363073443041421ULL,1871854672088537064ULL,7675957823933400996ULL,1871854672088537064ULL,13673158234934803076ULL,1871854711553775488ULL,5961139863418481633ULL,1871854711553775488ULL,6038363148542770286ULL,1871854711553775488ULL,13673158274400057472ULL,2463678837290300783ULL,8941596402284982641ULL,2463678837290300783ULL,10478898523446202728ULL,2463678837290300783ULL,11362903378706486837ULL,3657437759215363906ULL,7674111474393060323ULL,5282687112576490636ULL,8035850825281265476ULL,5282687112576490636ULL,13673158234934803076ULL,5282687112576490636ULL,16067074752306730735ULL,5961139784487988934ULL,5961139784487988934ULL,5961139784487988934ULL,6038363033977787146ULL,5961139784487988934ULL,13673158195469564652ULL,5961139784487988934ULL,14260316634768525029ULL,5961139784487988934ULL,17827671482396297765ULL,5961139823953243209ULL,5961139823953243209ULL,5961139823953243209ULL,6038363033977787146ULL,5961139823953243209ULL,6038363073443041421ULL,5961139823953243209ULL,13673158234934803076ULL,5961139823953243209ULL,14260316709868269745ULL,5961139823953243209ULL,17827671521861536189ULL,5961139863418481633ULL,5961139863418481633ULL,5961139863418481633ULL,6038363148542770286ULL,5961139863418481633ULL,13673158274400057472ULL,5961139863418481633ULL,14260316749333524020ULL,5961139863418481633ULL,17827671561326790464ULL,6038363033977787146ULL,6038363033977787146ULL,6038363033977787146ULL,7673971598074960276ULL,6038363033977787146ULL,8035845615867701176ULL,6038363033977787146ULL,8035850631785773665ULL,6038363033977787146ULL,13673158195469564652ULL,6038363033977787146ULL,14260316634768525029ULL,6038363033977787146ULL,17827671482396297765ULL,6038363073443041421ULL,6038363073443041421ULL,6038363073443041421ULL,6038363148542770286ULL,6038363073443041421ULL,13673158234934803076ULL,6038363073443041421ULL,14260316709868269745ULL,6038363073443041421ULL,14260316749333524020ULL,6038363073443041421ULL,17827671521861536189ULL,6038363148542770286ULL,6038363148542770286ULL,6038363148542770286ULL,8035850825281265476ULL,6038363148542770286ULL,13673158274400057472ULL,6038363148542770286ULL,14260316749333524020ULL,6038363148542770286ULL,17827671482396297765ULL,6038363148542770286ULL,17827671561326790464ULL,6514915489235633155ULL,9048548968183620866ULL,6514935704883662610ULL,9048548968183620866ULL,7673971598074960276ULL,7828651979274512736ULL,7673971598074960276ULL,10869912308522309619ULL,7673981859039011146ULL,7828652093839495876ULL,7673981859039011146ULL,10869917055571065940ULL,7675341284526946866ULL,8035840599951705168ULL,7675341323992201141ULL,8035845461837463640ULL,7675341553394202404ULL,8035845615867701176ULL,7675957784468146600ULL,8035845809365269468ULL,7675957823933400996ULL,7828651979274512736ULL,7675957823933400996ULL,10478883477746483419ULL,7675957823933400996ULL,10869912308522309619ULL,7675957938498399987ULL,8035845615867701176ULL,7675957938498399987ULL,10869917055571065940ULL,7675957977963638411ULL,8035850631785773665ULL,7675958017428892686ULL,8035850825281265476ULL,7828651979274512736ULL,8035850592320519390ULL,7828652093839495876ULL,8035850785816011201ULL,8035840599951705168ULL,8035845461837463640ULL,8035840599951705168ULL,8035845615867701176ULL,8035840599951705168ULL,8035850825281265476ULL,8035840599951705168ULL,11904335031529889982ULL,8035845461837463640ULL,8035845615867701176ULL,8035845461837463640ULL,8035850825281265476ULL,8035845461837463640ULL,11904335031529889982ULL,8035845615867701176ULL,8035850825281265476ULL,8035845615867701176ULL,13673158234934803076ULL,8035845809365269468ULL,8035850631785773665ULL,8035845809365269468ULL,8035850825281265476ULL,8035850592320519390ULL,10869912308522309619ULL,8035850631785773665ULL,8035850631785773665ULL,8035850631785773665ULL,8035850825281265476ULL,8035850631785773665ULL,13673158195469564652ULL,10478883169683931866ULL,10869901930940837960ULL,10478883477746483419ULL,10869907063474254878ULL,11904335031529889982ULL,11904335031529889982ULL,13673158195469564652ULL,13673158195469564652ULL,13673158195469564652ULL,14260316634768525029ULL,13673158195469564652ULL,17827671482396297765ULL,13673158234934803076ULL,13673158234934803076ULL,13673158234934803076ULL,14260316709868269745ULL,13673158234934803076ULL,17827671521861536189ULL,13673158274400057472ULL,13673158274400057472ULL,13673158274400057472ULL,14260316749333524020ULL,13673158274400057472ULL,17827671561326790464ULL,17536377943509457944ULL,17536377943509457944ULL};
inline int kccwf_core_init(void)
{
	kccwf_disable();
	kccwf_current.mode = KCCWF_DISABLE_MODE;
	int ret = 0;
	kccwf_report_init(recorded_pairs,sizeof(recorded_pairs)/sizeof(recorded_pairs[0]),&reported_info);
	kccwf_report_init(recorded_pairs_gfs2,sizeof(recorded_pairs_gfs2)/sizeof(recorded_pairs_gfs2[0]),&reported_info);
	kccwf_report_init(recorded_pairs_btrfs,sizeof(recorded_pairs_gfs2)/sizeof(recorded_pairs_gfs2[0]),&reported_info);
	kccwf_report_init(recorded_pairs_f2fs,sizeof(recorded_pairs_f2fs)/sizeof(recorded_pairs_gfs2[0]),&reported_info);
	race_pairs_init(&concurrent_pairs);
	ret = race_pairs_monitor_init(&rp_monitor, &concurrent_pairs);
	if (ret < 0) {
		goto fail_exit;
	}
	// kccwf_tracker_init();
	kccwf_current.mode = KCCWF_MONITOR_MODE;
	pr_info("KCCWF module loaded successfully, the init mode is %d\n",
		kccwf_current.mode);
	kccwf_enable();
	return 0;
fail_exit:
	pr_info("KCCWF module load failed, the init mode is %d\n",
		kccwf_current.mode);
	kccwf_enable();
	return -ENOMEM;
}

inline void kccwf_core_exit(void)
{
	kccwf_disable();
	// traker exit
	kccwf_enable();
}

/* is the addr in stack */
static __always_inline int is_stack_pointer(unsigned long addr)
{
	unsigned long irq_stack_start =
		(unsigned long)per_cpu(pcpu_hot.hardirq_stack_ptr,
				       raw_smp_processor_id()) +
		8 - IRQ_STACK_SIZE;
	unsigned long irq_stack_end = irq_stack_start + IRQ_STACK_SIZE;
	unsigned long stack_start = (unsigned long)current->stack;
	unsigned long stack_end = stack_start + THREAD_SIZE;
	return (addr >= irq_stack_start && addr < irq_stack_end) ||
	       (addr >= stack_start && addr < stack_end);
}

static int handler_thread_func(void *data)
{
	while (rp_monitor.thread_running) {
		wait_event(rp_monitor.wq, rp_monitor.thread_running);
		spin_lock_irqsave(&rp_monitor.write_rb.consume_lock,
				  rp_monitor.write_rb.consume_lock_flags);
		unsigned long pos =
			atomic_long_fetch_inc(&rp_monitor.write_rb.tail);
		spin_unlock_irqrestore(&rp_monitor.write_rb.consume_lock,
				       rp_monitor.write_rb.consume_lock_flags);
		process_write_access(
			&rp_monitor,
			(write_access_info_t *)&rp_monitor.write_rb.buffer[pos],
			&concurrent_pairs);
	}
	return 0;
}

int kccwf_rp_monitor_thread_init(void)
{
	if (rp_monitor.thread_running) {
		return 0;
	}
	rp_monitor.handler_thread = kthread_run(
		handler_thread_func, &rp_monitor, "kccwf_handler_thread");
	if (IS_ERR(rp_monitor.handler_thread)) {
		pr_err("Failed to create handler thread\n");
		return PTR_ERR(rp_monitor.handler_thread);
	}
	rp_monitor.thread_running = true;
	return 0;
}

static void ftrace_log_access(access_info_t *var_access_info)
{
	trace_printk("[KCCWF] log access: is_write=%d, file_line=%d, tid=%d, size=%d, "
	             "delay_time=%d, is_skip=%d, var_name=%lu, var_addr=%p, "
	             "call_stack_hash=%lu, access_time=%lu, sn=%d\n",
	             var_access_info->is_write,
	             var_access_info->file_line,
	             var_access_info->tid,
	             var_access_info->size,
	             var_access_info->delay_time,
	             var_access_info->is_skip,
	             var_access_info->var_name,
	             var_access_info->var_addr,
	             var_access_info->call_stack_hash,
	             var_access_info->access_time,
	             var_access_info->sn);
}

#ifdef UAF_DETECT_MODE
void kccwf_rec_mem_access(const volatile void *addr, unsigned long var_name,
			  int is_write, int file_line, int size)
{
	ktime_t start, end;
	u64 delta;
	int delay_time = 0;
	access_info_t var_access_info;
	unsigned long irq_flags = 0;
	local_irq_save(irq_flags);
	unsigned long stack_entries[NUM_STACK_ENTRIES];
	int num_entries;
	if (current->kccwf_disable_count || !addr ||
	    kccwf_current.mode == KCCWF_DISABLE_MODE) {
		goto exit_label;
	}
	if (is_stack_pointer((unsigned long)addr)) {
		goto exit_label;
	}
	// try the best to ensure order
	ktime_t access_time = ktime_get();
	pid_t tid = current->pid;
	smp_mb();
	if (kccwf_current.mode == KCCWF_MONITOR_MODE) {
		if (get_random_u32_below(100) < DELAY_PROBABILITY) {
			delay_time = get_random_u32_below(80);
		} else {
			delay_time = 0;
		}
		goto monitor;
	}
	// log part fuzz mode
	if (!is_write) {
		if (KCCWF_DEBUG)
			atomic_long_inc(
				&kccwf_statistical_var.kccwf_read_count);
		read_access_info_t read_access_info = {
			.var_name = var_name,
			.var_addr = addr,
			.access_time = access_time,
			.tid = tid,
			.size = size,
			.file_line = file_line
		};
		// [optimize me the following loop spend too much time, maybe we can use hash to improve it ] 不急 应该还好 主要的耗时还是在后面watchpoint的处理上
		if (kccwf_current.mode == KCCWF_LOG_MODE) {
			if (!atomic_read(&rp_monitor.rp_thread_initialized)) {
				if (atomic_cmpxchg(
					    &rp_monitor.rp_thread_initialized,
					    0, 1) == 0) {
					kccwf_rp_monitor_thread_init();
				}
				return;
			}
			log_read_access(&rp_monitor, &read_access_info);
			goto exit_label;
		} else if (kccwf_current.mode == KCCWF_VALIDATE_MODE) {
			if (atomic_read(&kccwf_current.kccwf_validate_times) >
			    KCCWF_MAX_VALIDAE_TIMES) {
				goto exit_label;
			}
			race_pair_t may_race_pair;
			may_race_pair.read_name = var_name;
			num_entries = stack_trace_save(stack_entries,
						       NUM_STACK_ENTRIES, 1);
			may_race_pair.call_stack_hash = kccwf_calc_stack_hash(
				stack_entries, num_entries);
			may_race_pair.sn = kccwf_fetch_inc_access_by_hash(
				var_name, may_race_pair.call_stack_hash);
			race_pair_entry_t *entry = race_pairs_find(
				&concurrent_pairs.checked_race, &may_race_pair,
				race_pair_match_name_and_stack);
			if (entry) {
				goto exit_label;
			}
			entry = race_pairs_find(&concurrent_pairs.may_race,
						&may_race_pair,
						race_pair_match_all);
			if (entry) {
				// Decide validate number per test
				int validate_times = atomic_fetch_inc(
					&kccwf_current.kccwf_validate_times);
				if (validate_times >= KCCWF_MAX_VALIDAE_TIMES) {
					goto exit_label;
				}

				printk(KERN_INFO
				       "Validate read_name %lu in sn %lu\n",
				       var_name, may_race_pair.sn);
				delay_time = KCCWF_TIME_WINDOW * 100;

				/* 插入到checked 并改变delay time * 这样是为了避免内存分配问题 */
				race_pair_t *checked_may_race_pair = kmalloc(
					sizeof(race_pair_t), GFP_ATOMIC);
				checked_may_race_pair->read_name = var_name;
				checked_may_race_pair->sn = may_race_pair.sn;
				checked_may_race_pair->call_stack_hash =
					may_race_pair.call_stack_hash;
				race_pairs_add(&concurrent_pairs.checked_race,
					       checked_may_race_pair,
					       race_pair_match_name_and_stack);
				goto monitor;
			}
		}

	} else {
		if (kccwf_current.mode == KCCWF_LOG_MODE) {
			if (!atomic_read(&rp_monitor.rp_thread_initialized)) {
				if (atomic_cmpxchg(
					    &rp_monitor.rp_thread_initialized,
					    0, 1) == 0) {
					kccwf_rp_monitor_thread_init();
				}
				return;
			}
			long pos = ring_buffer_produce(&rp_monitor.write_rb);
			write_access_info_t *w_buffer =
				(write_access_info_t *)
					rp_monitor.write_rb.buffer;
			if (pos >= 0) {
				w_buffer[pos].access_time = access_time;
				w_buffer[pos].tid = tid;
				w_buffer[pos].var_addr = addr;
				w_buffer[pos].num_entries = stack_trace_save(
					w_buffer[pos].stack_entries,
					NUM_STACK_ENTRIES, 0);
			}
			smp_mb();
			// wake_up(&rp_monitor.wq);
			// [Think about it!]
			delay_time = 0;
			goto exit_label;
		} else if (kccwf_current.mode == KCCWF_VALIDATE_MODE) {
			goto monitor;
		}
	}

	if (delay_time == 0) {
		goto exit_label;
	}
monitor:
	var_access_info.is_write = is_write;
	var_access_info.file_line = file_line;
	var_access_info.var_name = var_name;
	var_access_info.size = size;
	var_access_info.var_addr = addr;
	var_access_info.call_stack_hash = 0;
	var_access_info.access_time = access_time;
	var_access_info.delay_time = delay_time;
	var_access_info.is_skip = 0;
	watchpoints_monitor(&var_access_info, read_watchpoints,
			    write_watchpoints, read_report_infos,
			    &read_report_lock, write_report_infos,
			    &write_report_lock, &reported_info);
exit_label:
	local_irq_restore(irq_flags);
}
EXPORT_SYMBOL(kccwf_rec_mem_access);
#else
void kccwf_rec_mem_access(const volatile void *addr, unsigned long var_name,
			  int is_write, int file_line, int size)
{
	ktime_t start, end;
	u64 delta;
	int delay_time = 0;
	access_info_t var_access_info;
	unsigned long irq_flags = 0;
	local_irq_save(irq_flags);
	unsigned long stack_entries[NUM_STACK_ENTRIES];
	int num_entries;
	if (current->kccwf_disable_count || !addr ||
	    kccwf_current.mode == KCCWF_DISABLE_MODE) {
		goto exit_label;
	}
	if (is_stack_pointer((unsigned long)addr)) {
		goto exit_label;
	}
	// try the best to ensure order
	ktime_t access_time = ktime_get();
	pid_t tid = current->pid;
	smp_mb();
	if (kccwf_current.mode == KCCWF_MONITOR_MODE) {
		if (is_write){
			delay_time = get_random_u32_below(800);
			goto monitor;
		}
		if (get_random_u32_below(100) < DELAY_PROBABILITY) {
			delay_time = get_random_u32_below(8);
			// delay_time=0;
		} else {
			delay_time = 0;
		}
		goto monitor;
	}
	// log part fuzz mode
	if (kccwf_current.mode == KCCWF_LOG_MODE) {
		var_access_info.is_write = is_write;
		var_access_info.file_line = file_line;
		var_access_info.var_name = var_name;
		var_access_info.size = size;
		var_access_info.var_addr = addr;
		var_access_info.call_stack_hash = 0;
		var_access_info.access_time = access_time;
		var_access_info.delay_time = delay_time;
		var_access_info.is_skip = 0;
		var_access_info.is_write = is_write;
		var_access_info.tid = tid;
		num_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
		var_access_info.call_stack_hash = kccwf_calc_stack_hash(stack_entries,num_entries);
		// var_access_info.sn = kccwf_fetch_inc_access_by_hash(var_name, var_access_info.call_stack_hash);
		ftrace_log_access(&var_access_info);
		goto exit_label;
	}
monitor:
	var_access_info.is_write = is_write;
	var_access_info.file_line = file_line;
	var_access_info.var_name = var_name;
	var_access_info.size = size;
	var_access_info.var_addr = addr;
	var_access_info.call_stack_hash = 0;
	var_access_info.access_time = access_time;
	var_access_info.delay_time = delay_time;
	var_access_info.is_skip = 0;
	watchpoints_monitor(&var_access_info, read_watchpoints,
			    write_watchpoints, read_report_infos,
			    &read_report_lock, write_report_infos,
			    &write_report_lock, &reported_info);
exit_label:
	local_irq_restore(irq_flags);
}
EXPORT_SYMBOL(kccwf_rec_mem_access);
#endif
void enable_kccwf_free_rec(void)
{
	current->kccwf_free_enable_count++;
}
EXPORT_SYMBOL(enable_kccwf_free_rec);

void disable_kccwf_free_rec(void)
{
	current->kccwf_free_enable_count--;
}
EXPORT_SYMBOL(disable_kccwf_free_rec);