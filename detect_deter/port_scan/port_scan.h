#ifndef __PORT_SCAN_H__
#define __PORT_SCAN_H__

#define  PORT_SCAN_BASE_CTL				346

#define PORT_SCAN_SO_SET_THRESHOLD		PORT_SCAN_BASE_CTL
#define PORT_SCAN_SO_SET_MAX				PORT_SCAN_SO_SET_THRESHOLD


#define PORT_SCAN_SO_GET_THRESHOLD		PORT_SCAN_BASE_CTL
#define PORT_SCAN_SO_GET_MAX+1			PORT_SCAN_SO_GET_THRESHOLD


#define PORT_SCAN_NUM  					10	// 时间间隔内访问不同port的个数 

struct st_cmd_port_scan
{
	u8 *zone_name;
	u8 flag_valid;	// 1=valid 0 = unvalid
	u32 threshold;	// 1-5000毫秒
	u32 default;		// 1=default_threshold, 0 = user self threshold 
};

struct st_port_scan_obj
{
	u32 sip;
	u32 dip;
	u16 dport[PORT_SCAN_NUM];
	s32 dport_num;			//port scan num
	unsigned long first_time;	//first skb of the ip come of the time
};


struct st_port_scan_node
{
	struct list_head *list;
	struct st_port_scan_obj obj;
};

#endif //end of __PORT_SCAN_H__

