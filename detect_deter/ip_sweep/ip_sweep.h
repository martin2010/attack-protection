#ifndef __IP_SWEEP_H__
#define __IP_SWEEP_H__

#define  IP_SWEEP_BASE_CTL			336

#define IP_SWEEP_SO_SET_THRESHOLD		IP_SWEEP_BASE_CTL
#define IP_SWEEP_SO_SET_MAX			IP_SWEEP_SO_SET_THRESHOLD


#define IP_SWEEP_SO_GET_THRESHOLD		IP_SWEEP_BASE_CTL
#define IP_SWEEP_SO_GET_MAX			IP_SWEEP_SO_GET_THRESHOLD


#define IP_SWEEP_NUM  				10	// 时间间隔内访问不同ip的个数 

struct st_cmd_ip_sweep
{
	u8 *zone_name;
	u8 flag_valid;
	u32 threshold;
	s32 def;
};

struct st_ip_sweep_obj
{
	u32 sip;			//sip address
	u32 dip[IP_SWEEP_NUM];
	s32 dip_num;			//address scan num
	unsigned long first_time;	//first skb of the ip come of the time
};


struct st_ip_sweep_node
{
	struct list_head list;
	struct st_ip_sweep_obj obj;
};

#endif //end of __IP_SWEEP_H__

