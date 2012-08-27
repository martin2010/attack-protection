#include <linux/in.h>
#include <linux/init.h>

#define TRASH_RECOVER_DEBUG				1
#define TRASH_RECOVER_DEBUG_W			1

s32 trash_recover_default_threshold = 2000;			//ºÁÃë

#ifdef TRASH_RECOVER_DEBUG 
#define dprintk printk
#else
#define dprintk
#endif

#ifdef TRASH_RECOVER_DEBUG_W
#define dwprintk printk
#else
#define dwprintk 
#endif

static void __trash_recover(void)
{
	s32 i;
	struct if_zone *zone = NULL;
	struct st_ip_sweep_node *ip_sweep = NULL;
	struct st_port_scan_node *port_scan = NULL;

	list_for_each_entry(zone, &zone_head, list)
	{
		if (zone->ip_sweep)
		{
			for (i = 0; i < IP_SWEEP_MAX_HASH; i++)
			{
				while(!list_empty(&zone->ip_sweep->head[i]))
				{
					ip_sweep = list_entry(zone->ip_sweep->head[i].next, struct st_ip_sweep_node, list);
					/* clear trash node */
					if (jiffies - ip_sweep->obj.first_time >= ip_sweep_default_threshold*2)
					{
						list_del(&ip_sweep->list);
						kfree(ip_sweep);
					}
				}
			}
		}
		if (zone->port_scan)
		{
			for (i = 0; i < PORT_SCAN_MAX_HASH; i++)
			{
				while(!list_empty(&zone->port_scan->head[i]))
				{
					port_scan = list_entry(zone->port_scan->head[i].next, struct st_port_scan_node, list);
					/* clear laji node */
					if (jiffies - port_scan->obj.first_time >= port_scan_default_threshold*2)
					{
						list_del(&port_scan->list);
						kfree(port_scan);
					}
				}
			}
		}
	}
	mod_timer(timer, jiffies+trash_recover_default_threshold);
}

static void trash_recover(void)
{
	write_lock_bh(&zone_rwlock);
	__trash_recover();
	write_unlock_bh(&zone_rwlock);
}


struct timer_list timer;

static init __init trash_recover_init(void)
{
	setup_timer(&timer, trash_recover, 0);
	timer.expires = jiffies + trash_recover_default_threshold;
	add_timer(&timer);

	return 0;
}

static exit __exit trash_recover_fin(void)
{
	del_timer(&timer);
}

MODULE_DESCRIPTION("trash recover");
MODULE_LICENSE("GPL");

module_init(trash_recover_init);
module_exit(trash_recover);

