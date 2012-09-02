#ifndef __ZONE_H__
#define __ZONE_H__

#include "../zone_screen.h"


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
	u8 zone_name[ZONE_NAME_LEN+1];
};



#endif /*end of __ZONE_H__*/
