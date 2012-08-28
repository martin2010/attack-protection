#include <linux/in.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/screen.h>

#include "ip_sweep.h"

#define IP_SWEEP_DEBUG			1
#define IP_SWEEP_DEBUG_W		1

DEFINE_RWLOCK(ip_sweep_rwlock);


s32 ip_sweep_default_threshold = 5;


#ifdef IP_SWEEP_DEBUG 
#define dprintk printk
#else
#define dprintk
#endif

#ifdef IP_SWEEP_DEBUG_W
#define dwprintk printk
#else
#define dwprintk 
#endif


static s32 get_hash(u32 ip)
{
	return ip % IP_SWEEP_MAX_HASH;
}

static struct st_ip_sweep_node * 
init_new_node(u32 sip, u32 dip)
{
	struct st_ip_sweep_node *new_node = NULL;

	new_node = kmalloc(GFP_ATOMIC, sizeof(struct st_ip_sweep_node));
	if (new_node == NULL)
	{
		return NULL;
	}
	new_node->obj.sip= sip;
//	new_node->obj.dip[0] = 0;
	new_node->obj.dip[0] = dip;
	new_node->obj.dip_num= 1;
	new_node->obj.first_time= jiffies;

	return new_node;
}

static s32 __ip_sweep(const struct iphdr *ipinfo, struct st_zone_ip_sweep *ip_sweep)
{
	s32 i, hash = 0;
	struct st_ip_sweep_node *ip_sweep_node = NULL;
	struct st_ip_sweep_node *new_node = NULL;

	hash = get_hash(ipinfo->saddr);

	list_for_each_entry(ip_sweep_node, &(ip_sweep->head[hash]), list)
	{
		if (ip_sweep_node->obj.sip == ipinfo->saddr)
		{
			if (jiffies - ip_sweep_node->obj.first_time <= ip_sweep->threshold)
			{
				/* ip sweep has start */
				if (ip_sweep_node->obj.dip_num >= IP_SWEEP_NUM)
				{
					return NF_DROP;
				}

				for (i = 0; i < ip_sweep_node->obj.dip_num && i < IP_SWEEP_NUM; i++)
				{
					if (ipinfo->daddr == ip_sweep_node->obj.dip[i])
					{
						return NF_ACCEPT;
					}
				}
				/* new dip, add to node */
				ip_sweep_node->obj.dip[ip_sweep_node->obj.dip_num] = ipinfo->daddr;
				ip_sweep_node->obj.dip_num++;
				/* ip sweep is starting, printk warning info, but forward this skb */
				if (ip_sweep_node->obj.dip_num >= IP_SWEEP_NUM)
				{
					dprintk(NIPQUAD_FMT" ip sweep!\n", NIPQUAD(ipinfo->saddr));
				}
			}
			else
			{
				ip_sweep_node->obj.dip[0] = ipinfo->daddr;
				ip_sweep_node->obj.dip_num = 1;
				ip_sweep_node->obj.first_time = jiffies;
			}
			return NF_ACCEPT;
		}
	}
	new_node = init_new_node(ipinfo->saddr, ipinfo->daddr);
	if (new_node == NULL)
	{
		return NF_ACCEPT;
	}
	list_add(&new_node->list, &ip_sweep->head[hash]);

	return NF_ACCEPT;
}

static s32 ip_sweep(const struct iphdr *ipinfo, struct st_zone_ip_sweep *ip_sweep)
{
	s32 ret;

	write_lock_bh(&ip_sweep_rwlock);
	ret = __ip_sweep(ipinfo, ip_sweep);
	write_unlock_bh(&ip_sweep_rwlock);

	return ret;
}

static u32 ip_sweep_hook(u32 hook,
	 struct sk_buff *skb,
	 const struct net_device *in,
	 const struct net_device *out,
	 s32 (*okfn)(struct sk_buff *))
{
	const struct iphdr *ipinfo = ip_hdr(skb);
	struct if_zone *zone;
	zone = in->zone;

	if (zone->ip_sweep == NULL)
		return NF_ACCEPT;

	if (ipinfo->protocol != IPPROTO_ICMP)
		return NF_ACCEPT;

	return ip_sweep(ipinfo, zone->ip_sweep);
}


static struct nf_hook_ops ip_sweep_ops[] __read_mostly = {
	{
		.hook		= ip_sweep_hook,
		.owner		= THIS_MODULE,
		.pf			= PF_INET,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority		= NF_IP_PRI_NAT_DST-1,
	},
};

static s32 zone_ip_sweep_init(struct st_zone_ip_sweep **zone_ip_sweep)
{
	s32 i;

	*zone_ip_sweep = kmalloc(sizeof(struct st_zone_ip_sweep), GFP_KERNEL);
	if (*zone_ip_sweep == NULL)
	{
		return -ENOMEM;
	}
	for (i = 0 ; i < IP_SWEEP_MAX_HASH; i++)
	{
		INIT_LIST_HEAD(&((*zone_ip_sweep)->head[i]));
	}
	
	return 0;
}
static void zone_ip_sweep_clean(struct st_zone_ip_sweep **zone_ip_sweep)
{
	if (*zone_ip_sweep != NULL)
	{
		kfree(*zone_ip_sweep);
		*zone_ip_sweep = NULL;
	}
}

static s32 set_ip_sweep(void __user *user, u32 len)
{
	s32 threshold;
	s32 size = sizeof(struct st_cmd_ip_sweep);
	struct if_zone *zone = NULL;
	struct st_cmd_ip_sweep ip_sweep;
	struct st_zone_ip_sweep *zone_ip_sweep = NULL;

	if (len != size)
	{
		printk("%s: length %d != size %d\n", __func__, len, size);
		return -EINVAL;
	}
	if (copy_from_user(&ip_sweep, user, len) != 0)
	{
		printk("%s: copy_from_user is err!\n", __func__);
		return -EFAULT;
	}

	zone = zone_get_by_name(ip_sweep.zone_name);
	if (zone == NULL)
	{
		return -EFAULT;
	}

	write_lock_bh(&ip_sweep_rwlock);
	if (ip_sweep.flag_valid == 1)
	{
		threshold = ip_sweep.threshold;
		if (ip_sweep.def == 1)
			threshold = ip_sweep_default_threshold;

		if (zone->ip_sweep == NULL)
		{
			if (zone_ip_sweep_init(&(zone->ip_sweep)) < 0)
			{
				write_unlock_bh(&ip_sweep_rwlock);
				zone_put(zone);
				return -ENOMEM;
			}
		}
		zone_ip_sweep = zone->ip_sweep;
		zone_ip_sweep->threshold = threshold;
	}
	else //ip_sweep.flag_valid==0
	{
		zone_ip_sweep_clean(&(zone->ip_sweep));
	}
	write_unlock_bh(&ip_sweep_rwlock);
	zone_put(zone);
	return 0;
}

static s32 get_ip_sweep_threshold(void __user * user, s32 * len)
{
	s32 ret = 0;
	s32 size = sizeof(struct st_cmd_ip_sweep);
	struct if_zone *zone = NULL;
	struct st_cmd_ip_sweep ip_sweep;

	if (*len != size)
	{
		printk("%s :length %d != size %d\n", __func__, *len, size);
		return -EINVAL;
	}
	if (copy_from_user(&ip_sweep, user, size) != 0)
	{
		printk("%s: copy from user err!\n", __func__);
		return -EFAULT;
	}

	zone = zone_get_by_name(ip_sweep.zone_name);
	if (zone == NULL)
	{
		return -EFAULT;
	}

	read_lock_bh(&ip_sweep_rwlock);
	ip_sweep.threshold = zone->ip_sweep->threshold;
	read_unlock_bh(&ip_sweep_rwlock);

	if (copy_to_user(user, &ip_sweep, *len) != 0)
	{
		printk("%s: copy to user err!\n", __func__);
		ret = -EFAULT;
	}

	zone_put(zone);
	return ret;
}

static s32 do_ip_sweep_set_ctl(struct sock *sk, s32 cmd, void __user *user, u32 len)
{
	s32 ret = 0;

	switch(cmd)
	{
		case IP_SWEEP_SO_SET_THRESHOLD:
			ret = set_ip_sweep(user, len);
			break;
		default:
			dprintk("ip sweep set opt: unknow request %i\n", cmd);
			ret = -EINVAL;
			break;
	}

	return ret;
}

static s32 do_ip_sweep_get_ctl(struct sock *sk, s32 cmd, void __user *user, s32 *len)
{
	s32 ret = 0;

	switch(cmd)
	{
		case IP_SWEEP_SO_GET_THRESHOLD:
			ret = get_ip_sweep_threshold(user, len);
			break;
		default:
			dprintk("ip sweep get opt: unknow request %i\n", cmd);
			ret = -EINVAL;
			break;
	}

	return ret;
}

static struct nf_sockopt_ops ip_sweep_sockopts = {
	.pf = PF_INET,
	.set_optmin = IP_SWEEP_BASE_CTL,
	.set_optmax = IP_SWEEP_SO_SET_MAX+1,
	.set = do_ip_sweep_set_ctl,
	.get_optmin = IP_SWEEP_BASE_CTL,
	.get_optmax = IP_SWEEP_SO_GET_MAX+1,
	.get = do_ip_sweep_get_ctl,
	.owner = THIS_MODULE,
};


static int __init ip_sweep_init(void)
{
	s32 ret = 0;

	ret = nf_register_hooks(ip_sweep_ops, ARRAY_SIZE(ip_sweep_ops));
	if (ret < 0)
	{
		printk("%s: ip sweep hook register failed!\n", __func__);
		goto out;
	}

	ret = nf_register_sockopt(&ip_sweep_sockopts);
	if (ret < 0)
	{
		printk("%s: ip sweep sockopt register failed!\n", __func__);
		goto out_unregister_hooks;
	}

	return ret;

out_unregister_hooks:
	nf_unregister_hooks(ip_sweep_ops, ARRAY_SIZE(ip_sweep_ops));
out:
	return ret;
}

static void __exit ip_sweep_fini(void)
{
	nf_unregister_sockopt(&ip_sweep_sockopts);

	nf_unregister_hooks(ip_sweep_ops, ARRAY_SIZE(ip_sweep_ops));
}

MODULE_DESCRIPTION("address scan");
MODULE_LICENSE("GPL");

module_init(ip_sweep_init);
module_exit(ip_sweep_fini);

