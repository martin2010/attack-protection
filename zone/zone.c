#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <net/sock.h>

#include "zone.h"

static struct list_head zone_head;
static DEFINE_RWLOCK(zone_rwlock);

#define ZONE_DEBUG  		1
#define ZONE_DEBUG_CONFIG  	1
#define ZONE_DEBUG_MATCH  	1

#ifdef ZONE_DEBUG
#define dprintk(x...) printk(x)
#else
#define dprintk(x...)
#endif
#ifdef ZONE_DEBUG_CONFIG
#define dcprintk(x...) printk(x)
#else
#define dcprintk(x...)
#endif
#ifdef ZONE_DEBUG_MATCH
#define dmprintk(x...) printk(x)
#else
#define dmprintk(x...)
#endif


static void __zone_put(struct if_zone *zone)
{
	atomic_dec(&zone->use);
}

void zone_put(struct if_zone *zone)
{
	write_lock_bh(&zone_rwlock);
	__zone_put(zone);
	write_unlock_bh(&zone_rwlock);
}
EXPORT_SYMBOL(zone_put);

struct if_zone *zone_get_by_name(s8 *name)
{
	struct if_zone *zone = NULL;
	read_lock_bh(&zone_rwlock);
	list_for_each_entry(zone, &zone_head, list)
	{
		if (strcmp(zone->sec_zone.name, name) == 0)
		{
			atomic_inc(&zone->use);
			read_unlock_bh(&zone_rwlock);
			return zone;
		}
	}
	read_unlock_bh(&zone_rwlock);
	return NULL;
}
EXPORT_SYMBOL(zone_get_by_name);

s32 zone_get_by_policy(struct if_zone *zone, struct st_sec_zone *sec_zone)
{

	if (zone == NULL || sec_zone == NULL)
	{
		printk("%s : parameter is err!\n", __func__);
		return -EINVAL;
	}

	read_lock_bh(&zone_rwlock);
	memcpy(sec_zone, &(zone->sec_zone), sizeof(struct st_sec_zone));
	read_unlock_bh(&zone_rwlock);

	return 0;
}
EXPORT_SYMBOL(zone_get_by_policy);

inline bool zone_match(struct if_zone *zone, const s8 *if_name)
{
	s32 i;

	dmprintk("if_name=%s\n", if_name);

	read_lock_bh(&zone_rwlock);
	for(i = 0; i < zone->sec_zone.if_num; i++)
	{
		if(strcmp(zone->sec_zone.if_name[i], if_name) == 0)
		{
			dprintk("zone:%s match!\n", zone->sec_zone.name);
			read_unlock_bh(&zone_rwlock);
			return true;
		}
	}
	
	read_unlock_bh(&zone_rwlock);
	return false;
}
EXPORT_SYMBOL(zone_match);

s32 zone_get_priority(const u8 *if_name, s32 *priority)
{
	s32 i;
	struct if_zone *zone = NULL;
	
	read_lock_bh(&zone_rwlock);
        list_for_each_entry(zone, &zone_head, list)
        {
		for (i = 0; i < zone->sec_zone.if_num; i++)
		{
			if (strcmp(zone->sec_zone.if_name[i], if_name) == 0)
			{
				*priority = zone->sec_zone.pri;
				read_unlock_bh(&zone_rwlock);
				return 0;
			}
		}
	}
	read_unlock_bh(&zone_rwlock);
	return -1;
}
EXPORT_SYMBOL(zone_get_priority);

static void zone_printk(struct if_zone *zone)
{
	s32 i;
	struct st_sec_zone *sec_zone = NULL;

	sec_zone = &(zone->sec_zone);

        if (sec_zone == NULL)
        {
                return;
        }

	dcprintk("name: %-10s use: %-4d  pri: %-8d", sec_zone->name, zone->use.counter, sec_zone->pri);
	
	dcprintk("interface:");
	for(i = 0; i < sec_zone->if_num; i++)
	{
		dcprintk("%-8s", sec_zone->if_name[i]);
	}

	dcprintk("\n");
}

/*
static void zone_add_if(struct if_zone *zone;)
{
	s32 i, err_num = 0;
	struct net_device *dev = NULL;

	for(i = 0; i < zone->sec_zone.if_num; i++)
	{
		dev = dev_get_by_name(zone->sec_zone.if_name[i]);
		if (dev == NULL)
			continue;
		dev->zone = zone;
	}
}

static void zone_del_if(struct if_zone *zone;)
{
	s32 i, err_num = 0;
	struct net_device *dev = NULL;

	for(i = 0; i < zone->sec_zone.if_num; i++)
	{
		dev = dev_get_by_name(zone->sec_zone.if_name[i]);
		if (dev == NULL)
			continue;
		dev->zone = zone;
	}
}
*/
static s32 zone_add_if(u8 *if_name, struct if_zone *zone)
{
	if (zone->sec_zone.if_num >= 10)
	{
		return -EFAULT;
	}

	strcpy(zone->sec_zone.if_name[zone->sec_zone.if_num++], if_name);

	return 0;
}

static void zone_del_if(u8 *if_name, struct if_zone *zone)
{
	s32 i;
	struct st_sec_zone tmp = {0};

	for (i = 0;i < zone->sec_zone.if_num; i++)
	{
		if (strcmp(zone->sec_zone.if_name[i], if_name) == 0)
		{
			memcpy(&tmp, zone->sec_zone.if_name[i+1], (ZONE_IF_NUM-(i+1))*(IF_NAME_SIZE+1));
			memcpy(zone->sec_zone.if_name[i], &tmp, (ZONE_IF_NUM-(i+1))*(IF_NAME_SIZE+1));
			break;
		}
	}
}

static s32 if_set_zone(void __user *user, s32 len)
{
	struct st_cmd_if_zone if_zone;
	struct if_zone *zone = NULL;
	struct net_device *dev = NULL;

	if (len != sizeof(struct st_cmd_if_zone))
	{
		printk("%s: length %d != size %d\n", __func__, len, sizeof(struct st_cmd_if_zone));
		return -EINVAL;
	}

	if (copy_from_user(&if_zone, user, len) != 0)
	{
		printk("%s: copy_from_user is err!\n", __func__);
		return -EFAULT;
	}

	zone = zone_get_by_name(if_zone.zone_name);
	if (zone == NULL)
	{
		printk("%s: zone %s is not eiestent!\n", __func__, if_zone.zone_name);
		return -EFAULT;
	}

	dev = dev_get_by_name(&init_net, if_zone.if_name);
	if (dev == NULL)
	{
		zone_put(zone);
		printk("%s: netdevice %s is not existent!\n", __func__, if_zone.if_name);
		return -EFAULT;
	}

	if (dev->zone)
	{
		zone_del_if(if_zone.if_name, dev->zone);
		zone_put(dev->zone);
		dev->zone = NULL;
	}

	dev->zone = zone;

	return zone_add_if(if_zone.if_name, zone);
}

static s32 zone_add(void __user *user, s32 len)
{
	struct if_zone *zone;
	struct if_zone *new_zone;

	if (len != sizeof(struct st_sec_zone))
	{
		printk("%s: length %d != size %d\n", __func__, len, sizeof(struct st_sec_zone));
		return -EINVAL;
	}

	new_zone = kmalloc(sizeof(struct if_zone), GFP_KERNEL);
	if (new_zone == NULL)
	{
		printk("%s: kmalloc sec zone is err!\n", __func__);
		return -ENOMEM;
	}
	memset(new_zone, 0, sizeof(struct if_zone));

	if (copy_from_user(&(new_zone->sec_zone), user, len) != 0)
	{
		kfree(new_zone);
		printk("%s: copy_from_user is err!\n", __func__);
		return -EFAULT;
	}

	if ((zone = zone_get_by_name(new_zone->sec_zone.name)) != NULL)
	{
		zone_put(zone);
		kfree(new_zone);
		printk("%s: zone %s is eiestent!\n", __func__, new_zone->sec_zone.name);
		return -EFAULT;
	}

	write_lock_bh(&zone_rwlock);
	atomic_set(&new_zone->use, 1);
	list_add_tail(&(new_zone->list), &zone_head);
	write_unlock_bh(&zone_rwlock);
	dcprintk("add zone: %s seccuss! \n", new_zone->sec_zone.name);
	return 0;
}

static void __zone_del(struct if_zone *zone)
{
	write_lock_bh(&zone_rwlock);
	if (atomic_dec_return(&zone->use) == 0)
	{
		list_del(&zone->list);
		dprintk("%s: free zone: %s\n", __func__, zone->sec_zone.name);
		kfree(zone);
	}
	else
	{
		atomic_inc(&zone->use);
	}
	write_unlock_bh(&zone_rwlock);
}

static s32 zone_del(void __user *user, s32 len)
{
	s32 size = sizeof(struct st_sec_zone);
	struct st_sec_zone sec_zone;
	struct if_zone *zone = NULL;

	if (len != size)
	{
		printk("%s: length %d != size %d\n", __func__, len, size);
		return -EINVAL;
	}

	if (copy_from_user(&sec_zone, user, len) != 0)
	{
		printk("%s: copy_from_user is err!\n", __func__);
		return -EFAULT;
	}

	zone = zone_get_by_name(sec_zone.name);
	if (zone == NULL)
	{
		printk("zone: %s is not esistent!\n", sec_zone.name);
		return -EFAULT;
	}

	zone_put(zone);//zone_get_by_name put 1
	__zone_del(zone);
	
	dcprintk("del zone: %s seccuss! \n", sec_zone.name);
	return 0;
}

static s32 zone_mod(void __user *user, s32 len)
{
	s32 size = sizeof(struct st_sec_zone);
	struct st_sec_zone sec_zone;
	struct if_zone *zone;

	if (len != size)
	{
		printk("%s: length %d != size %d\n", __func__, len, size);
		return -EINVAL;
	}

	if (copy_from_user(&sec_zone, user, len) != 0)
	{
		printk("%s: copy_from_user is err!\n", __func__);
		return -EFAULT;
	}
	
	zone = zone_get_by_name(sec_zone.name);
	if (zone == NULL)
	{
		printk("zone: %s is not esistent!\n", sec_zone.name);
		return -EFAULT;
	}

	write_lock_bh(&zone_rwlock);
	memcpy(&(zone->sec_zone), &sec_zone, sizeof(struct st_sec_zone));
	write_unlock_bh(&zone_rwlock);

	zone_put(zone);

	dcprintk("modify zone: %s seccuss! \n", sec_zone.name);
	return 0;
}

static s32 zone_get(void __user * user, s32 * len)
{
	s32 ret = 0;
	s32 size = sizeof(struct st_sec_zone);
	struct st_sec_zone sec_zone;
	struct if_zone *zone;

	if (*len != size)
	{
		printk("%s :length %d != size %d\n", __func__, *len, size);
		return -EINVAL;
	}
	if (copy_from_user(&sec_zone, user, size) != 0)
	{
		printk("%s: copy from user err!\n", __func__);
		return -EFAULT;
	}

	zone = zone_get_by_name(sec_zone.name);
	if (zone == NULL)
	{
		printk("%s: zone %s not found\n", __func__, sec_zone.name);
		return -EFAULT;
	}
	
	if (copy_to_user(user, &(zone->sec_zone), *len) != 0)
	{
		printk("%s: copy to user err!\n", __func__);
		ret = -EFAULT;
	}

	zone_put(zone);
	return ret;
}

static s32 if_get_zone(void __user * user, s32 * len)
{
	s32 ret = 0;
	s32 size = sizeof(struct st_cmd_if_zone);
	struct st_cmd_if_zone if_zone;
	struct net_device *dev;

	if (*len != size)
	{
		printk("%s :length %d != size %d\n", __func__, *len, size);
		return -EINVAL;
	}
	if (copy_from_user(&if_zone, user, size) != 0)
	{
		printk("%s: copy from user err!\n", __func__);
		return -EFAULT;
	}

	dev = dev_get_by_name(&init_net, if_zone.if_name);
	if (dev == NULL)
	{
		printk("%s: netdevice %s not found\n", __func__, if_zone.if_name);
		return -EFAULT;
	}

	if (dev->zone)
	{
		strcpy(if_zone.zone_name, dev->zone->sec_zone.name);
	}
	else
	{
		strcpy(if_zone.zone_name, "null");
	}
	

	if (copy_to_user(user, &(if_zone), *len) != 0)
	{
		printk("%s: copy to user err!\n", __func__);
		ret = -EFAULT;
	}

	return ret;
}

static s32 zone_get_all(void __user *user, s32 *len)
{
	return 0;
}


static s32 zone_show(void __user * user, s32 len)
{
	s32 ret = 0;
	s32 size = sizeof(struct st_sec_zone);
	struct st_sec_zone sec_zone;
	struct if_zone *zone;

	if (len != size)
	{
		dprintk("%s :length %d != size %d\n", __func__, len, size);
		return -EINVAL;
	}
	if (copy_from_user(&sec_zone, user, size) != 0)
	{
		dprintk("%s: copy from user err!\n", __func__);
		return -EFAULT;
	}

        read_lock_bh(&zone_rwlock);
        list_for_each_entry(zone, &zone_head, list)
        {
                if (strcmp(zone->sec_zone.name, sec_zone.name) == 0)
                {
			zone_printk(zone);
                        ret = 1;
        	}
	}
        read_unlock_bh(&zone_rwlock);

	if (ret != 1)
	{
		dprintk("%s: zone %s not found\n", __func__, sec_zone.name);
		return -EFAULT;
	}
	
	return 0;
}

static s32 zone_show_all(void __user * user, s32 len)
{
	struct if_zone *zone = NULL;


	read_lock_bh(&zone_rwlock);
	list_for_each_entry(zone, &zone_head, list)
	{
		zone_printk(zone);
	}
	read_unlock_bh(&zone_rwlock);
	return 0;
}

static void zone_clean(void)
{
	struct if_zone *zone = NULL;

	write_lock_bh(&zone_rwlock);

	while(!list_empty(&zone_head))
	{
		zone = list_entry(zone_head.next, struct if_zone, list);
		dprintk("%s: free zone: %s\n", __func__, zone->sec_zone.name);
		list_del(&zone->list);
		kfree(zone);
	}

	write_unlock_bh(&zone_rwlock);
}

static s32 do_zone_set_ctl(struct sock *sk, s32 cmd, void __user *user, u32 len)
{
	s32 ret = 0;

	switch(cmd)
	{
		case ZONE_SO_SET_ADD_ZONE:
			ret = zone_add(user, len);
			break;
		case ZONE_SO_SET_DEL_ZONE:
			ret = zone_del(user, len);
			break;
		case ZONE_SO_SET_MOD_ZONE:
			ret = zone_mod(user, len);
			break;
		case ZONE_SO_IF_SET_ZONE:
			ret = if_set_zone(user, len);
			break;
		case ZONE_SO_SET_FLUSH_ALL_ZONE:
			zone_clean();
			break;
		case ZONE_SO_SET_SHOW_ZONE:
			ret = zone_show(user, len);
			break;
		case ZONE_SO_SET_SHOW_ALL_ZONE:
			ret = zone_show_all(user, len);
			break;
		default:
			dprintk("zone set opt: unknow request %i\n", cmd);
			ret = -EINVAL;
			break;
	}

	return ret;
}

static s32 do_zone_get_ctl(struct sock *sk, s32 cmd, void __user *user, s32 *len)
{
	s32 ret = 0;

	switch(cmd)
	{
		case ZONE_SO_GET_ZONE:
			ret = zone_get(user, len);
			break;
		case ZONE_SO_IF_GET_ZONE:
			ret = if_get_zone(user, len);
			break;
		case ZONE_SO_GET_ALL_ZONE:
			ret = zone_get_all(user, len);
			break;
		default:
			dprintk("zone get opt: unknow request %i\n", cmd);
			ret = -EINVAL;
			break;
	}

	return ret;
}


static struct nf_sockopt_ops zone_sockopts = {
	.pf = PF_INET,
	.set_optmin = ZONE_BASE_CTL,
	.set_optmax = ZONE_SO_SET_MAX+1,
	.set = do_zone_set_ctl,
	.get_optmin = ZONE_BASE_CTL,
	.get_optmax = ZONE_SO_GET_MAX+1,
	.get = do_zone_get_ctl,
	.owner = THIS_MODULE,
};



s32 __init zone_init(void)
{
	s32 ret;

	dprintk("zone module init ...\n");

	ret = nf_register_sockopt(&zone_sockopts);
	if (ret < 0)
	{
		printk("%s: zone sockopt register failed!\n", __func__);
		return ret;
	}

	INIT_LIST_HEAD(&zone_head);

	return 0;
}

void __exit zone_exit(void)
{
	dprintk("%s: zone module exit...\n", __func__);

	nf_unregister_sockopt(&zone_sockopts);
	
	zone_clean();
}

MODULE_LICENSE("GPL");
module_init(zone_init);
module_exit(zone_exit);


