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

#include "os_sniffer.h"

#define OS_SNIFFER_DEBUG		1
#define OS_SNIFFER_DEBUG_W		1

DEFINE_RWLOCK(os_sniffer_rwlock);


s32 os_sniffer_default_threshold = 5;


#ifdef OS_SNIFFER_DEBUG 
#define dprintk printk
#else
#define dprintk
#endif

#ifdef OS_SNIFFER_DEBUG_W
#define dwprintk printk
#else
#define dwprintk 
#endif


static bool os_sniffer_syn_fin(const struct tcphdr *th)
{
	return (th->syn && th->fin);
}
static bool os_sniffer_fin_no_ack(const struct tcphdr *th)
{
	return (th->fin && !th->ack);
}
static bool os_sniffer_tcp_no_flag(const struct tcphdr *th)
{
	return (!th->cwr && !th->ece && !th->urg && !th->ack && 
		!th->psh && !th->rst && !th->syn && !th->fin);
}

static u32
os_sniffer_hook(u32 hook,
	 struct sk_buff *skb,
	 const struct net_device *in,
	 const struct net_device *out,
	 s32 (*okfn)(struct sk_buff *))
{
	const struct iphdr *ipinfo = ip_hdr(skb);
	const struct tcphdr *tcpinfo = tcp_hdr(skb);
	//网络设备结构新加入域的指针
	struct if_zone *zone;
	zone = in->zone;

	if (ipinfo->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	if (zone->syn_fin == true)
	{
		if(os_sniffer_syn_fin(tcpinfo) == true)
		{
			dprintk("zone:%s match syn-fin \n", zone->sec_zone.name);
			return NF_DROP;
		}
	}

	if (zone->fin_no_ack == true)
	{
		if (os_sniffer_fin_no_ack(tcpinfo) == true)
		{
			dprintk("zone:%s match fin-no-ack \n", zone->sec_zone.name);
			return NF_DROP;
		}
	}

	if (zone->tcp_no_flag == true)
	{
		if (os_sniffer_tcp_no_flag(tcpinfo) == true)
		{
			dprintk("zone:%s match tcp-no-flag \n", zone->sec_zone.name);
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}


static struct nf_hook_ops os_sniffer_ops[] __read_mostly = {
	{
		.hook		= os_sniffer_hook,
		.owner		= THIS_MODULE,
		.pf			= PF_INET,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority		= NF_IP_PRI_NAT_DST-1,
	},
};


/*flag == true, syn-fin is ok; flag==false, syn-fin is no ok*/
static s32 set_syn_fin(void __user *user, u32 len)
{
	struct st_cmd_os_sniffer oss;
	struct if_zone *zone = NULL;
	s32 size = sizeof(struct st_cmd_os_sniffer);

	if (len != size)
	{
		printk("%s: length %d != size %d\n", __func__, len, size);
		return -EINVAL;
	}
	if (copy_from_user(&oss, user, len) != 0)
	{
		printk("%s: copy_from_user is err!\n", __func__);
		return -EFAULT;
	}

	zone = zone_get_by_name(oss.zone_name);
	if (zone == NULL)
	{
		return -EFAULT;
	}
	zone->syn_fin = oss.flag;
	zone_put(zone);

	return 0;
}
static s32 set_fin_no_ack(void __user *user, u32 len)
{
	struct st_cmd_os_sniffer oss;
	struct if_zone *zone = NULL;
	s32 size = sizeof(struct st_cmd_os_sniffer);

	if (len != size)
	{
		printk("%s: length %d != size %d\n", __func__, len, size);
		return -EINVAL;
	}
	if (copy_from_user(&oss, user, len) != 0)
	{
		printk("%s: copy_from_user is err!\n", __func__);
		return -EFAULT;
	}

	zone = zone_get_by_name(oss.zone_name);
	if (zone == NULL)
	{
		return -EFAULT;
	}
	zone->fin_no_ack = oss.flag;
	zone_put(zone);

	return 0;
}
static s32 set_tcp_no_flag(void __user *user, u32 len)
{
	struct st_cmd_os_sniffer oss;
	struct if_zone *zone = NULL;
	s32 size = sizeof(struct st_cmd_os_sniffer);

	if (len != size)
	{
		printk("%s: length %d != size %d\n", __func__, len, size);
		return -EINVAL;
	}
	if (copy_from_user(&oss, user, len) != 0)
	{
		printk("%s: copy_from_user is err!\n", __func__);
		return -EFAULT;
	}

	zone = zone_get_by_name(oss.zone_name);
	if (zone == NULL)
	{
		return -EFAULT;
	}
	zone->tcp_no_flag = oss.flag;
	zone_put(zone);

	return 0;
}

static s32 get_syn_fin(void __user * user, s32 * len)
{
	s32 ret = 0;
	s32 size = sizeof(struct st_cmd_os_sniffer);
	struct if_zone *zone = NULL;
	struct st_cmd_os_sniffer oss;

	if (*len != size)
	{
		printk("%s :length %d != size %d\n", __func__, *len, size);
		return -EINVAL;
	}
	if (copy_from_user(&oss, user, size) != 0)
	{
		printk("%s: copy from user err!\n", __func__);
		return -EFAULT;
	}

	zone = zone_get_by_name(oss.zone_name);
	if (zone == NULL)
	{
		return -EFAULT;
	}

	oss.flag = zone->syn_fin;

	if (copy_to_user(user, &oss, *len) != 0)
	{
		printk("%s: copy to user err!\n", __func__);
		ret = -EFAULT;
	}

	zone_put(zone);
	return ret;
}
static s32 get_fin_no_ack(void __user * user, s32 * len)
{
	s32 ret = 0;
	s32 size = sizeof(struct st_cmd_os_sniffer);
	struct if_zone *zone = NULL;
	struct st_cmd_os_sniffer oss;

	if (*len != size)
	{
		printk("%s :length %d != size %d\n", __func__, *len, size);
		return -EINVAL;
	}
	if (copy_from_user(&oss, user, size) != 0)
	{
		printk("%s: copy from user err!\n", __func__);
		return -EFAULT;
	}

	zone = zone_get_by_name(oss.zone_name);
	if (zone == NULL)
	{
		return -EFAULT;
	}

	oss.flag = zone->fin_no_ack;

	if (copy_to_user(user, &oss, *len) != 0)
	{
		printk("%s: copy to user err!\n", __func__);
		ret = -EFAULT;
	}

	zone_put(zone);
	return ret;
}
static s32 get_tcp_no_flag(void __user * user, s32 * len)
{
	s32 ret = 0;
	s32 size = sizeof(struct st_cmd_os_sniffer);
	struct if_zone *zone = NULL;
	struct st_cmd_os_sniffer oss;

	if (*len != size)
	{
		printk("%s :length %d != size %d\n", __func__, *len, size);
		return -EINVAL;
	}
	if (copy_from_user(&oss, user, size) != 0)
	{
		printk("%s: copy from user err!\n", __func__);
		return -EFAULT;
	}

	zone = zone_get_by_name(oss.zone_name);
	if (zone == NULL)
	{
		return -EFAULT;
	}

	oss.flag = zone->tcp_no_flag;

	if (copy_to_user(user, &oss, *len) != 0)
	{
		printk("%s: copy to user err!\n", __func__);
		ret = -EFAULT;
	}

	zone_put(zone);
	return ret;
}

static s32 do_os_sniffer_set_ctl(struct sock *sk, s32 cmd, void __user *user, u32 len)
{
	s32 ret = 0;

	switch(cmd)
	{
		case OS_SNIFFER_SO_SET_SYN_FIN:
			ret = set_syn_fin(user, len);
			break;
		case OS_SNIFFER_SO_SET_FIN_NO_ACK:
			ret = set_fin_no_ack(user, len);
			break;
		case OS_SNIFFER_SO_SET_TCP_NO_FLAG:
			ret = set_tcp_no_flag(user, len);
			break;
		default:
			dprintk("os sniffer set opt: unknow request %i\n", cmd);
			ret = -EINVAL;
			break;
	}

	return ret;
}

static s32 do_os_sniffer_get_ctl(struct sock *sk, s32 cmd, void __user *user, s32 *len)
{
	s32 ret = 0;

	switch(cmd)
	{
		case OS_SNIFFER_SO_GET_SYN_FIN:
			ret = get_syn_fin(user, len);
			break;
		case OS_SNIFFER_SO_GET_FIN_NO_ACK:
			ret = get_fin_no_ack(user, len);
			break;
		case OS_SNIFFER_SO_GET_TCP_NO_FLAG:
			ret = get_tcp_no_flag(user, len);
			break;
		default:
			dprintk("os sniffer get opt: unknow request %i\n", cmd);
			ret = -EINVAL;
			break;
	}

	return ret;
}

static struct nf_sockopt_ops os_sniffer_sockopts = {
	.pf = PF_INET,
	.set_optmin = OS_SNIFFER_BASE_CTL,
	.set_optmax = OS_SNIFFER_SO_SET_MAX+1,
	.set = do_os_sniffer_set_ctl,
	.get_optmin = OS_SNIFFER_BASE_CTL,
	.get_optmax = OS_SNIFFER_SO_GET_MAX+1,
	.get = do_os_sniffer_get_ctl,
	.owner = THIS_MODULE,
};

static int __init os_sniffer_init(void)
{
	s32 ret = 0;

	ret = nf_register_hooks(os_sniffer_ops, ARRAY_SIZE(os_sniffer_ops));
	if (ret < 0)
	{
		printk("%s: os sniffer hook register failed!\n", __func__);
		goto out;
	}

	ret = nf_register_sockopt(&os_sniffer_sockopts);
	if (ret < 0)
	{
		printk("%s: os sniffer sockopt register failed!\n", __func__);
		goto out_unregister_hooks;
	}

	return ret;

out_unregister_hooks:
	nf_unregister_hooks(os_sniffer_ops, ARRAY_SIZE(os_sniffer_ops));
out:
	return ret;
}

static void __exit os_sniffer_fini(void)
{
	nf_unregister_sockopt(&os_sniffer_sockopts);

	nf_unregister_hooks(os_sniffer_ops, ARRAY_SIZE(os_sniffer_ops));
}

MODULE_DESCRIPTION("os sniffer");
MODULE_LICENSE("GPL");

module_init(os_sniffer_init);
module_exit(os_sniffer_fini);

