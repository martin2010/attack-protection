#ifndef __SCREEN_H__
#define __SCREEN_H__

#include <linux/if_ether.h>
#include <linux/timer.h>
#include <linux/netfilter/x_tables.h>



#define ZONE_BASE_CTL			1000


#define ZONE_NAME_LEN 			32
#define IF_NAME_SIZE			16
#define ZONE_IF_NUM			16




#ifndef NIPQUAD
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif



struct st_sec_zone
{
	u32 id;
        u8  name[ZONE_NAME_LEN+1];
	u32 pri;
        u32 if_num;
        u8 if_name[ZONE_IF_NUM][IF_NAME_SIZE+1];
};

struct if_zone
{
	struct list_head list;
	atomic_t use;
	struct st_zone_ip_sweep *ip_sweep;
	struct st_zone_port_scan *port_scan;
	bool syn_fin;
	bool fin_no_ack;
	bool tcp_no_flag;
	struct st_sec_zone sec_zone;
};



#endif /*end of __SCREEN_H__*/
