#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/etherdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_new_ct.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <net/sock.h>
//#include <linux/nf_screen.h>
#include "packet_attr.h"

DEFINE_RWLOCK(packet_attr_rwlock);
unsigned int packet_attr_enable 		= 1;
unsigned int ICMP_FRAGMENT_FLAG 		= 0;
unsigned int ICMP_LARGE_PACKET_FLAG 		= 0;
unsigned int IP_BAD_OPTION_FLAG 		= 0;
unsigned int IP_UNKNOW_PROTOCOL_FLAG 		= 0;
unsigned int IP_BLOCK_FRAG_FLAG 		= 0;
unsigned int SYN_FRAGMENT_FLAG			= 0;


#define PA_DEBUG_CONFIG
#define PA_DEBUG_MATCH

#ifdef PA_DEBUG
	#define dprintk printk
#else
	#define dprintk(args...)
#endif

#ifdef PA_DEBUG_MATCH
	#define dmprintk printk
#else
	#define dmprintk(args...)
#endif

#ifdef PA_DEBUG_CONFIG
	#define dcprintk printk
#else
	#define dcprintk(args...)
#endif


static void packet_attr_printk(void)
{
#ifdef PA_DEBUG
	printk("name                  enable");
	printk("icmp-fragment         %d\n", ICMP_FRAGMENT_FLAG);
	printk("icmp-large-packet     %d\n", ICMP_LARGE_PACKET_FLAG);
	printk("ip-bad-option         %d\n", IP_BAD_OPTION_FLAG);
	printk("ip-unknow-protocol    %d\n", IP_UNKNOW_PROTOCOL_FLAG);
	printk("ip-block-frag         %d\n", IP_BLOCK_FRAG_FLAG);
	printk("syn-fragment          %d\n", SYN_FRAGMENT_FLAG);
#endif
}

static void packet_attr_cmd_print(struct st_packet_attr *pa)
{
#ifdef PA_DEBUG_CONFIG
	printk("icmp-fragment         %d\n", pa->icmp_fragment);
	printk("icmp-large-packet     %d\n", pa->icmp_large_packet);
	printk("ip-bad-option         %d\n", pa->ip_bad_option);
	printk("ip-unknow-protocol    %d\n", pa->ip_unknow_protocol);
	printk("ip-block-frag         %d\n", pa->ip_block_frag);
	printk("syn-fragment          %d\n", pa->syn_fragment);
#endif
}

static s32 packet_attr_query(void __user * user, s32 * len)
{
	s32 ret = 0;
	s32 size = sizeof(struct st_packet_attr);
	struct st_packet_attr *pa = NULL;
	
	if (*len != size)
	{
		printk("%s :length %d != size %d\n", __func__, *len, size);
		return -EINVAL;
	}

	pa = (struct st_packet_attr*)kmalloc(size, GFP_KERNEL);
	if (pa == NULL)
	{
		printk("%s: kmalloc st_packet_attr failed!\n", __func__);
		return -ENOMEM;
	}

	read_lock_bh(&packet_attr_rwlock);
	pa->icmp_fragment = ICMP_FRAGMENT_FLAG;
	pa->icmp_large_packet = ICMP_LARGE_PACKET_FLAG;
	pa->ip_bad_option = IP_BAD_OPTION_FLAG;
	pa->ip_unknow_protocol = IP_UNKNOW_PROTOCOL_FLAG;
	pa->ip_block_frag = IP_BLOCK_FRAG_FLAG;
	pa->syn_fragment = SYN_FRAGMENT_FLAG;
	read_unlock_bh(&packet_attr_rwlock);
	

	if (copy_to_user(user, pa, *len) != 0)
	{
		printk("%s: copy to user err!\n", __func__);
		ret = -EFAULT;
	}

	kfree(pa);
	return ret;
}

static s32 packet_attr_show(void __user * user, s32 len)
{
	read_lock_bh(&packet_attr_rwlock);
	packet_attr_printk();
	read_unlock_bh(&packet_attr_rwlock);
	return 0;
}

static s32 packet_attr_set_enable_flag(void __user * user, s32 len)
{
	u32 enable_flag = 0;
	s32 size = sizeof(u32);

	if (len != size)
	{
		printk("%s :length %d != size %d\n", __func__, len, size);
		return -EINVAL;
	}

	if (copy_from_user(&enable_flag, user, size) != 0)
	{
		printk("%s: copy from user err!\n", __func__);
		return -EFAULT;
	}

        read_lock_bh(&packet_attr_rwlock);
      	packet_attr_enable = enable_flag;
	read_unlock_bh(&packet_attr_rwlock);

	dmprintk("%s: packet_attr set enable falg = %u success!\n", __func__, enable_flag);
	return 0;
}

static s32 packet_attr_get_enable_flag(void __user * user, s32 *len)
{
	u32 enable_flag = 0;
	s32 size = sizeof(u32);

	if (*len != size)
	{
		printk("%s :length %d != size %d\n", __func__, *len, size);
		return -EINVAL;	
	}

	enable_flag = packet_attr_enable;

	if (copy_to_user(user, &enable_flag, *len) != 0)
	{
		printk("%s : copy to user err!\n", __func__);
		return -EFAULT;
	}

	printk("%s: packet_attr get enable falg = %u success!\n", __func__, enable_flag);
	return 0;
}

static s32 packet_attr_set_icmp_fragment_flag(void __user * user, s32 len)
{
	u32 enable_flag = 0;
	s32 size = sizeof(u32);

	if (len != size)
	{
		printk("%s :length %d != size %d\n", __func__, len, size);
		return -EINVAL;
	}

	if (copy_from_user(&enable_flag, user, size) != 0)
	{
		printk("%s: copy from user err!\n", __func__);
		return -EFAULT;
	}

        read_lock_bh(&packet_attr_rwlock);
      	ICMP_FRAGMENT_FLAG = enable_flag;
	read_unlock_bh(&packet_attr_rwlock);

	dcprintk("%s: packet_attr set icmp-fragment flag = %u success!\n", __func__, enable_flag);
	return 0;
}

static s32 packet_attr_get_icmp_fragment_flag(void __user * user, s32 *len)
{
	u32 enable_flag = 0;
	s32 size = sizeof(u32);

	if (*len != size)
	{
		printk("%s :length %d != size %d\n", __func__, *len, size);
		return -EINVAL;	
	}

	enable_flag = ICMP_FRAGMENT_FLAG;

	if (copy_to_user(user, &enable_flag, *len) != 0)
	{
		printk("%s : copy to user err!\n", __func__);
		return -EFAULT;
	}

	printk("%s: packet_attr get icmp-fragment falg = %u success!\n", __func__, enable_flag);
	return 0;
}

static s32 packet_attr_set_icmp_large_packet_flag(void __user * user, s32 len)
{
	u32 enable_flag = 0;
	s32 size = sizeof(u32);

	if (len != size)
	{
		printk("%s :length %d != size %d\n", __func__, len, size);
		return -EINVAL;
	}

	if (copy_from_user(&enable_flag, user, size) != 0)
	{
		printk("%s: copy from user err!\n", __func__);
		return -EFAULT;
	}

        read_lock_bh(&packet_attr_rwlock);
      	ICMP_LARGE_PACKET_FLAG = enable_flag;
	read_unlock_bh(&packet_attr_rwlock);

	dmprintk("%s: packet_attr set icmp-large-packet flag = %u success!\n", __func__, enable_flag);
	return 0;
}

static s32 packet_attr_get_icmp_larte_packet_flag(void __user * user, s32 *len)
{
	u32 enable_flag = 0;
	s32 size = sizeof(u32);

	if (*len != size)
	{
		printk("%s :length %d != size %d\n", __func__, *len, size);
		return -EINVAL;	
	}

	enable_flag = ICMP_LARGE_PACKET_FLAG;

	if (copy_to_user(user, &enable_flag, *len) != 0)
	{
		printk("%s : copy to user err!\n", __func__);
		return -EFAULT;
	}

	printk("%s: packet_attr get icmp-large-packet falg = %u success!\n", __func__, enable_flag);
	return 0;
}

static s32 packet_attr_set_ip_bad_option_flag(void __user * user, s32 len)
{
	u32 enable_flag = 0;
	s32 size = sizeof(u32);

	if (len != size)
	{
		printk("%s :length %d != size %d\n", __func__, len, size);
		return -EINVAL;
	}

	if (copy_from_user(&enable_flag, user, size) != 0)
	{
		printk("%s: copy from user err!\n", __func__);
		return -EFAULT;
	}

        read_lock_bh(&packet_attr_rwlock);
      	IP_BAD_OPTION_FLAG = enable_flag;
	read_unlock_bh(&packet_attr_rwlock);

	dmprintk("%s: packet_attr set ip-bad-option flag = %u success!\n", __func__, enable_flag);
	return 0;
}

static s32 packet_attr_get_ip_bad_option_flag(void __user * user, s32 *len)
{
	u32 enable_flag = 0;
	s32 size = sizeof(u32);

	if (*len != size)
	{
		printk("%s :length %d != size %d\n", __func__, *len, size);
		return -EINVAL;	
	}

	enable_flag = IP_BAD_OPTION_FLAG;

	if (copy_to_user(user, &enable_flag, *len) != 0)
	{
		printk("%s : copy to user err!\n", __func__);
		return -EFAULT;
	}

	printk("%s: packet_attr get ip-bad-option falg = %u success!\n", __func__, enable_flag);
	return 0;
}

static s32 packet_attr_set_ip_unknow_protocol_flag(void __user * user, s32 len)
{
	u32 enable_flag = 0;
	s32 size = sizeof(u32);

	if (len != size)
	{
		printk("%s :length %d != size %d\n", __func__, len, size);
		return -EINVAL;
	}

	if (copy_from_user(&enable_flag, user, size) != 0)
	{
		printk("%s: copy from user err!\n", __func__);
		return -EFAULT;
	}

        read_lock_bh(&packet_attr_rwlock);
      	IP_UNKNOW_PROTOCOL_FLAG = enable_flag;
	read_unlock_bh(&packet_attr_rwlock);

	dmprintk("%s: packet_attr set ip-unknow-protocol falg = %u success!\n", __func__, enable_flag);
	return 0;
}

static s32 packet_attr_get_ip_unknow_protocol_flag(void __user * user, s32 *len)
{
	u32 enable_flag = 0;
	s32 size = sizeof(u32);

	if (*len != size)
	{
		printk("%s :length %d != size %d\n", __func__, *len, size);
		return -EINVAL;	
	}

	enable_flag = IP_UNKNOW_PROTOCOL_FLAG;

	if (copy_to_user(user, &enable_flag, *len) != 0)
	{
		printk("%s : copy to user err!\n", __func__);
		return -EFAULT;
	}

	printk("%s: packet_attr get ip-unknow-protocol falg = %u success!\n", __func__, enable_flag);
	return 0;
}

static s32 packet_attr_set_ip_block_frag_flag(void __user * user, s32 len)
{
	u32 enable_flag = 0;
	s32 size = sizeof(u32);

	if (len != size)
	{
		printk("%s :length %d != size %d\n", __func__, len, size);
		return -EINVAL;
	}

	if (copy_from_user(&enable_flag, user, size) != 0)
	{
		printk("%s: copy from user err!\n", __func__);
		return -EFAULT;
	}

        read_lock_bh(&packet_attr_rwlock);
        IP_BLOCK_FRAG_FLAG = enable_flag;
	read_unlock_bh(&packet_attr_rwlock);

	dmprintk("%s: packet_attr set ip-block-frag falg = %u success!\n", __func__, enable_flag);
	return 0;
}

static s32 packet_attr_get_ip_block_frag_flag(void __user * user, s32 *len)
{
	u32 enable_flag = 0;
	s32 size = sizeof(u32);

	if (*len != size)
	{
		printk("%s :length %d != size %d\n", __func__, *len, size);
		return -EINVAL;	
	}

	enable_flag = packet_attr_enable;

	if (copy_to_user(user, &enable_flag, *len) != 0)
	{
		printk("%s : copy to user err!\n", __func__);
		return -EFAULT;
	}

	printk("%s: packet_attr get enable falg = %u success!\n", __func__, enable_flag);
	return 0;
}

static s32 packet_attr_set_syn_fragment_flag(void __user * user, s32 len)
{
	u32 enable_flag = 0;
	s32 size = sizeof(u32);

	if (len != size)
	{
		printk("%s :length %d != size %d\n", __func__, len, size);
		return -EINVAL;
	}

	if (copy_from_user(&enable_flag, user, size) != 0)
	{
		printk("%s: copy from user err!\n", __func__);
		return -EFAULT;
	}

        read_lock_bh(&packet_attr_rwlock);
      	SYN_FRAGMENT_FLAG = enable_flag;
	read_unlock_bh(&packet_attr_rwlock);

	dmprintk("%s: packet_attr set syn-fragment flag = %u success!\n", __func__, enable_flag);
	return 0;
}

static s32 packet_attr_get_syn_fragment_flag(void __user * user, s32 *len)
{
	u32 enable_flag = 0;
	s32 size = sizeof(u32);

	if (*len != size)
	{
		printk("%s :length %d != size %d\n", __func__, *len, size);
		return -EINVAL;	
	}

	enable_flag = SYN_FRAGMENT_FLAG;

	if (copy_to_user(user, &enable_flag, *len) != 0)
	{
		printk("%s : copy to user err!\n", __func__);
		return -EFAULT;
	}

	printk("%s: packet_attr get syn-fragment falg = %u success!\n", __func__, enable_flag);
	return 0;
}

static s32 do_packet_attr_set_ctl(struct sock *sk, s32 cmd, void __user *user, u32 len)
{
	s32 ret = 0;
	
	switch(cmd)
	{
		case PACKET_ATTR_SO_SET_ICMP_FRAGMENT_FLAG:
			ret = packet_attr_set_icmp_fragment_flag(user, len);
			break;
		case PACKET_ATTR_SO_SET_ICMP_LARGE_PACKET_FLAG:
			ret = packet_attr_set_icmp_large_packet_flag(user, len);
			break;
		case PACKET_ATTR_SO_SET_IP_BAD_OPTION_FLAG:
			ret = packet_attr_set_ip_bad_option_flag(user, len);
			break;
		case PACKET_ATTR_SO_SET_IP_UNKNOW_PROTOCOL_FLAG:
			packet_attr_set_ip_unknow_protocol_flag(user, len);
			break;
		case PACKET_ATTR_SO_SET_IP_BLOCK_FRAG_FLAG:
			packet_attr_set_ip_block_frag_flag(user, len);
			break;
		case PACKET_ATTR_SO_SET_SYN_FRAGMENT_FLAG:
			packet_attr_set_syn_fragment_flag(user, len);
			break;
		case PACKET_ATTR_SO_SET_ENABLE_FLAG:
			ret = packet_attr_set_enable_flag(user, len);
			break;
		case PACKET_ATTR_SO_SET_SHOW:
			ret = packet_attr_show(user, len);
			break;
		default:
			printk("port packet_attr set opt: unknow request \"%i\"\n", cmd);
			ret = -EINVAL;
			break;
	}

	return ret;
}

static s32 do_packet_attr_get_ctl(struct sock *sk, s32 cmd, void __user *user, s32 *len)
{
	s32 ret = 0;

	switch(cmd)
	{
		case PACKET_ATTR_SO_GET:
			ret = packet_attr_query(user, len);
			break;
		case PACKET_ATTR_SO_GET_ENABLE_FLAG:
			ret = packet_attr_get_enable_flag(user, len);
			break;
		default:
			printk("packet_attr get opt: unknow request \"%i\"\n", cmd);
			ret = -EINVAL;
			break;
	}

	return ret;
}

static struct nf_sockopt_ops packet_attr_sockopts = {
	.pf = PF_INET,
	.set_optmin = PACKET_ATTR_BASE_CTL,
	.set_optmax = PACKET_ATTR_SO_SET_MAX+1,
	.set = do_packet_attr_set_ctl,
	.get_optmin = PACKET_ATTR_BASE_CTL,
	.get_optmax = PACKET_ATTR_SO_GET_MAX+1,
	.get = do_packet_attr_get_ctl,
	.owner = THIS_MODULE,
};

/*****************packet_attr netfilter match  start*******************/

static void dmprint_packet_attr(void)
{
	packet_attr_printk();
}

static u32 icmp_fragment_filter(struct sk_buff *skb)
{
	return ip_hdr(skb)->frag_off && htons(IP_MF | IP_OFFSET);
}

static u32 icmp_large_packet_filter(struct sk_buff *skb)
{
	return ip_hdr(skb)->tot_len > 1024;
}

static u32 ip_bad_option_filter(struct sk_buff *skb)
{
	return ip_hdr(skb)->ihl > 5;
}

static u32 ip_unknow_protocol_filter(struct sk_buff *skb)
{
	return ip_hdr(skb)->protocol > 137;
}

static u32 ip_block_frag_filter(struct sk_buff *skb)
{
	return ip_hdr(skb)->frag_off && htons(IP_MF | IP_OFFSET);
}

static u32 syn_fragment_filter(struct sk_buff *skb)
{
	if (tcp_hdr(skb)->syn)
		return ip_hdr(skb)->frag_off && htons(IP_MF | IP_OFFSET);
	return 0;
}

static u32 packet_attr_match(u32 hook, 
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			s32 (*okfn)(struct sk_buff*))
{
	u32 ret = 0;
	const struct iphdr *ipinfo;

	dmprintk("%s: skb=%p come packet_attr filter!\n", __func__, skb);

	if (!packet_attr_enable)
	{
		dmprintk("%s: packet_attr function is disable, skb accept\n", __func__);
		return NF_ACCEPT;
	}

	ipinfo = ip_hdr(skb);

	if (ipinfo->protocol == 1 && ICMP_FRAGMENT_FLAG)
	{
		ret = icmp_fragment_filter(skb);
		if (ret != 0)
		{
			dmprintk("icmp-fragment is screen, skb drop\n");
			return NF_DROP;
		}
	}

	if (ipinfo->protocol == 1 && ICMP_LARGE_PACKET_FLAG)
	{
		ret = icmp_large_packet_filter(skb);
		if (ret != 0)
		{
			dmprintk("icmp-large-packet is screen, skb drop\n");
			return NF_DROP;
		}
	}

	if (IP_BAD_OPTION_FLAG)
	{
		ret = ip_bad_option_filter(skb);
		if (ret != 0)
		{
			dmprintk("ip-bad-option is screen, skb drop\n");
			return NF_DROP;
		}
	}

	if (IP_UNKNOW_PROTOCOL_FLAG)
	{
		ret = ip_unknow_protocol_filter(skb);
		if (ret != 0)
		{
			dmprintk("ip-unknow-protocol is screen, skb drop\n");
			return NF_DROP;
		}
	}

	if (IP_BLOCK_FRAG_FLAG)
	{
		ret = ip_block_frag_filter(skb);
		if (ret != 0)
		{
			dmprintk("ip-block-frag is screen, skb drop\n");
			return NF_DROP;
		}
	}

	if (ipinfo->protocol == 6 && SYN_FRAGMENT_FLAG)
	{
		ret = syn_fragment_filter(skb);
		if (ret != 0)
		{
			dmprintk("syn-fragment is screen, skb drop\n");
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops packet_attr_ops[] __read_mostly = {
	{	.hook = packet_attr_match,
		.owner = THIS_MODULE,
		.pf = PF_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER-2,
	},
};

/*****************packet_attr netfilter match  end*********************/

s32 __init packet_attr_init(void)
{
	s32 ret;

	printk("Packet attribute protection init ...\n");

	ret = nf_register_sockopt(&packet_attr_sockopts);
	if (ret < 0)
	{
		printk("%s: nf packet_attr sockopt register failed!\n", __func__);
		return ret;
	}

	ret = nf_register_hooks(packet_attr_ops, ARRAY_SIZE(packet_attr_ops));
	if (ret < 0)
	{
		nf_unregister_sockopt(&packet_attr_sockopts);
		printk("packet_attr hook register failed!\n");
		return ret;
	}

	printk("Packet attribute protection init ok!\n");
	return 0;
}

void __exit packet_attr_exit(void)
{
	printk("Packet attribute protection exit ...\n");

	nf_unregister_hooks(packet_attr_ops, ARRAY_SIZE(packet_attr_ops));

	nf_unregister_sockopt(&packet_attr_sockopts);
	
	printk("Packet attribute protection exit ok!\n");
}

MODULE_LICENSE("GPL");
module_init(packet_attr_init);
module_exit(packet_attr_exit);


