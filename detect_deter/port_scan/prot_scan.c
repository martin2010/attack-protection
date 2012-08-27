#include <linux/in.h>
#include <linux/init.h>
#include <linux/screen.h>

#include "port_scan.h"

#define PORT_SCAN_DEBUG			1
#define PORT_SCAN_DEBUG_W			1
s32 port_scan_default_threshold  =	5;			//毫秒

DEFINE_RWLOCK(port_scan_rwlock);



#ifdef PORT_SCAN_DEBUG 
#define dprintk printk
#else
#define dprintk
#endif

#ifdef PORT_SCAN_DEBUG_W
#define dwprintk printk
#else
#define dwprintk 
#endif


static s32 get_hash(u32 sip, u32 dip)
{
	return (sip + dip) % PORT_SCAN_MAX_HASH;
}

static struct st_port_scan_node * 
init_new_node(u32 sip, u32 dip, u16 dport)
{
	struct st_port_scan_node *new_node = NULL;

	new_node = kmalloc(GFP_ATOMIC, sizeof(struct st_port_scan_node));
	if (new_node == NULL)
	{
		return NULL;
	}
	new_node.obj.sip= sip;
	new_node.obj.dip = dip;
	new_node.obj.dport[0] = dport;
	new_node.obj.dport_num= 1;
	new_node.obj.first_time= jiffies;

	return new_node;
}

static s32 port_scan(const struct iphdr *ipinfo, struct tcphdr *tcpinfo, 
			struct st_zone_port_scan *port_scan)
{
	s32 i, hash = 0;
	struct st_port_scan_node *port_scan_node = NULL;
	struct st_port_scan_node *new_node = NULL;

	hash = get_hash(ipinfo->saddr, ipinfo->daddr);

	list_for_each_entry(port_scan_node, &(port_scan->head[hash]), list)
	{
		if (port_scan_node->obj.sip == ipinfo->saddr &&
			port_scan_node->obj.dip == ipinfo->daddr)
		{
			if (jiffies - port_scan_node->obj.first_time <= port_scan->threshold)
			{
				/* port scan has start */
				if (port_scan_node->obj.dport_num >= PORT_SCAN_NUM)
				{
					return NF_DROP;
				}

				for (i = 0; i < port_scan_node->obj.dport_num, i < PORT_SCAN_NUM; i++)
				{
					if (tcpinfo->dest == port_scan_node->obj.dport[i])
					{
						return NF_ACCEPT;
					}
				}
				/* new dport, add to node */
				port_scan_node->obj.dip[port_scan_node->obj.dport_num] = ipinfo->daddr;
				port_scan_node->obj.dport_num++;
				/* ip sweep is starting, printk warning info, but forward this skb */
				if (port_scan_node->obj.dport_num >= PORT_SCAN_NUM)
				{
					dprintk(NIPQUAD_FMT" port scan!\n", NIPQUAD(ipinfo->saddr));
				}
			}
			else
			{
				port_scan_node->obj.dport[0] = tcpinfo->dest;
				port_scan_node->obj.dport_num = 1;
				port_scan_node->obj.first_time = jiffies;
			}
			return NF_ACCEPT;
		}
	}
	new_node = init_new_node(ipinfo->saddr, ipinfo->daddr, tcpinfo->dest);
	if (new_node == NULL)
	{
		return NF_ACCEPT;
	}
	list_add(new_node, &port_scan->head[hash]);

	return NF_ACCEPT;
}

static s32 __port_scan(const struct iphdr *ipinfo, struct tcphdr *tcpinfo, 
			struct st_zone_port_scan *port_scan)
{
	s32 ret;

	write_lock_bh(&port_scan_rwlock);
	ret = port_scan(ipinfo, tcpinfo, port_scan);
	write_unlock_bh(&port_scan_rwlock);

	return ret;
}

static u32 port_scan_hook(u32 hook,
	 struct sk_buff *skb,
	 const struct net_device *in,
	 const struct net_device *out,
	 s32 (*okfn)(struct sk_buff *))
{
	const struct iphdr *ipinfo = ip_hdr(skb);
	const struct tcphdr *tcpinfo = tcp_hdr(skb);
	//  网络设备结构新加入域的指针
	struct if_zone *zone;
	zone = in->zone;

	// 此域端口扫描没开启
	if (zone->port_scan == NULL)
		return NF_ACCEPT;

	if (ipinfo->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	if (!tcpinfo->syn)
		return NF_ACCEPT;

	return port_scan(ipinfo, tcpinfo, zone->port_scan);
}

static struct nf_hook_ops port_scan_ops[] __read_mostly = {
	{
		.hook		= port_scan_hook,
		.owner		= THIS_MODULE,
		.pf			= PF_INET,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority		= NF_IP_PRI_NAT_DST-2,
	},
};

static s32 zone_port_scan_init(struct st_zone_port_scan **zone_port_scan)
{
	s32 i;

	*zone_port_scan = kmalloc(sizeof(struct st_zone_port_scan), GFP_KERNEL);
	if (*zone_port_scan == NULL)
	{
		return -ENOMEM;
	}
	for (i = 0 ; i < PORT_SCAN_MAX_HASH; i++)
	{
		INIT_LIST_HEAD(&((*zone_port_scan)->head[i]));
	}
	
	return 0;
}
static void zone_port_scan_clean(struct st_zone_port_scan **zone_port_scan)
{
	if (*zone_port_scan != NULL)
	{
		kfree(*zone_port_scan);
		*zone_port_scan = NULL;
	}
}

static s32 set_port_scan(void __user *user, s32 len)
{
	s32 threshold;
	s32 size = sizeof(struct st_cmd_port_scan);
	struct if_zone *zone = NULL;
	struct st_cmd_port_scan port_scan;
	struct st_zone_port_scan *zone_port_scan = NULL;

	if (len != size)
	{
		printk("%s: length %d != size %d\n", __func__, len, size);
		return -EINVAL;
	}
	if (copy_from_user(&port_scan, user, len) != 0)
	{
		printk("%s: copy_from_user is err!\n", __func__);
		return -EFAULT;
	}

	zone = zone_get_by_name(port_scan.zone_name);
	if (zone == NULL)
	{
		return -EFAULT;
	}

	write_lock_bh(&port_scan_lock);
	if (port_scan.flag_valid == 1)
	{
		threshold = port_scan.threshold;
		if (port_scan.default == 1)
			threshold = port_scan_default_threshold;

		if (zone->port_scan == NULL)
		{
			if (zone_port_scan_init(&(zone->port_scan)) < 0)
			{
				write_unlock_bh(&port_scan_lock);
				zone_put(zone);
				return -ENOMEM;
			}
		}
		zone_port_scan = zone->port_scan;
		zone_port_scan->threshold = threshold;
	}
	else //port_scan.flag_valid==0
	{
		zone_port_scan_clean(&(zone->port_scan));
	}
	write_unlock_bh(&port_scan_lock);

	return 0;
}

static s32 get_port_scan_threshold(void __user * user, s32 * len)
{
	s32 ret = 0;
	s32 size = sizeof(struct st_cmd_port_scan);
	struct if_zone *zone = NULL;
	struct st_cmd_port_scan port_scan;

	if (*len != size)
	{
		printk("%s :length %d != size %d\n", __func__, *len, size);
		return -EINVAL;
	}
	if (copy_from_user(&port_scan, user, size) != 0)
	{
		printk("%s: copy from user err!\n", __func__);
		return -EFAULT;
	}

	zone = zone_get_by_name(port_scan.zone_name);
	if (zone == NULL)
	{
		return -EFAULT;
	}

	read_lock_bh(&port_scan_rwlock);
	port_scan.threshold = zone->port_scan->threshold;
	read_unlock_bh(&port_scan_rwlock);

	if (copy_to_user(user, &port_scan, *len) != 0)
	{
		printk("%s: copy to user err!\n", __func__);
		ret = -EFAULT;
	}

	zone_put(zone);
	return ret;
}

static s32 do_port_scan_set_ctl(struct sock *sk, s32 cmd, void __user *user, u32 len)
{
	s32 ret = 0;

	switch(cmd)
	{
		case PORT_SCAN_SO_SET_THRESHOLD:
			ret = set_port_scan(user, len);
			break;
		default:
			dprintk("ip sweep set opt: unknow request %i\n", cmd);
			ret = -EINVAL;
			break;
	}

	return ret;
}

static s32 do_port_scan_get_ctl(struct sock *sk, s32 cmd, void __user *user, s32 *len)
{
	s32 ret = 0;

	switch(cmd)
	{
		case PORT_SCAN_SO_GET_THRESHOLD:
			ret = get_port_scan_threshold(user, len);
			break;
		default:
			dprintk("ip sweep get opt: unknow request %i\n", cmd);
			ret = -EINVAL;
			break;
	}

	return ret;
}

static struct nf_sockopt_ops port_scan_sockopts = {
	.pf = PF_INET,
	.set_optmin = PORT_SCAN_BASE_CTL,
	.set_optmax = PORT_SCAN_SO_SET_MAX+1,
	.set = do_port_scan_set_ctl,
	.get_optmin = PORT_SCAN_BASE_CTL,
	.get_optmax = PORT_SCAN_SO_GET_MAX+1,
	.get = do_port_scan_get_ctl,
	.owner = THIS_MODULE,
};


static init __init port_scan_init(void)
{
	s32 ret = 0;

	ret = nf_register_hooks(port_scan_ops, ARRAY_SIZE(port_scan_ops));
	if (ret < 0)
	{
		printk("%s: ip sweep hook register failed!\n", __func__);
		goto out;
	}

	ret = nf_register_sockopt(&port_scan_sockopts);
	if (ret < 0)
	{
		printk("%s: ip sweep sockopt register failed!\n", __func__);
		goto out_unregister_hooks;
	}

	return ret;

out_unregister_hooks:
	nf_unregister_hooks(port_scan_ops, ARRAY_SIZE(port_scan_ops));
out:
	return ret;
}

static exit __exit port_scan_fini(void)
{
	nf_unregister_sockopt(&port_scan_sockopts);

	nf_unregister_hooks(port_scan_ops, ARRAY_SIZE(port_scan_ops));
}

MODULE_DESCRIPTION("address scan");
MODULE_LICENSE("GPL");

module_init(port_scan_init);
module_exit(port_scan_fini);

