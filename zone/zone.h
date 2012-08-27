#ifndef __ZONE_H__
#define __ZONE_H__

#include <linux/screen.h>

#define ZONE_BASE_CTL 296

#define ZONE_SO_SET_ADD_ZONE (ZONE_BASE_CTL)
#define ZONE_SO_SET_DEL_ZONE (ZONE_BASE_CTL + 1)
#define ZONE_SO_SET_MOD_ZONE (ZONE_BASE_CTL + 2)
#define ZONE_SO_IF_SET_ZONE (ZONE_BASE_CTL + 3)
#define ZONE_SO_SET_FLUSH_ALL_ZONE (ZONE_BASE_CTL + 4)
#define ZONE_SO_SET_SHOW_ZONE (ZONE_BASE_CTL + 5)
#define ZONE_SO_SET_SHOW_ALL_ZONE (ZONE_BASE_CTL + 6)
#define ZONE_SO_SET_MAX (ZONE_SO_SET_SHOW_ALL_ZONE)

#define ZONE_SO_GET_ZONE (ZONE_BASE_CTL)
#define ZONE_SO_IF_GET_ZONE (ZONE_BASE_CTL+1)
#define ZONE_SO_GET_ALL_ZONE (ZONE_BASE_CTL + 2)
#define ZONE_SO_GET_MAX (ZONE_SO_GET_ALL_ZONE)

struct st_cmd_if_zone
{
	u8 if_name[IF_NAME_SIZE+1];
	u8 zone_name[PF_NAME_LEN+1];
};

/*
struct st_zone_node{
	struct list_head list;
	atomic_t use;
	struct st_zone_ip_sweep *ip_sweep;
	struct st_zone_port_scan *port_scan;
	bool syn_fin;
	bool fin_no_ack;
	bool tcp_no_flag;
	struct st_sec_zone zone;
};
*/


#endif /*end of __ZONE_H__*/
