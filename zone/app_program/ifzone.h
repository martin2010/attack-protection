#ifndef _SEC_ZONE_H_
#define _SEC_ZONE_H_

#define ZONE_NAME_LEN 32
#define ZONE_IF_NUM 16 
#define IF_NAME_SIZE 16

#define SEC_ZONE_BASE_CTL 1000

#define SEC_ZONE_SO_SET_ADD_ZONE (SEC_ZONE_BASE_CTL)
#define SEC_ZONE_SO_SET_DEL_ZONE (SEC_ZONE_BASE_CTL + 1)
#define SEC_ZONE_SO_SET_MOD_ZONE (SEC_ZONE_BASE_CTL + 2)
#define SEC_ZONE_SO_IF_SET_ZONE (SEC_ZONE_BASE_CTL + 3)
#define SEC_ZONE_SO_SET_FLUSH_ALL_ZONE (SEC_ZONE_BASE_CTL + 4)
#define SEC_ZONE_SO_SET_SHOW_ZONE (SEC_ZONE_BASE_CTL + 5)
#define SEC_ZONE_SO_SET_SHOW_ALL_ZONE (SEC_ZONE_BASE_CTL + 6)
#define SEC_ZONE_SO_SET_MAX (SEC_ZONE_SO_SET_SHOW_ALL_OBJ)

#define SEC_ZONE_SO_GET_ZONE (SEC_ZONE_BASE_CTL)
#define SEC_ZONE_SO_IF_GET_ZONE (SEC_ZONE_BASE_CTL + 1)
#define SEC_ZONE_SO_GET_ALL_ZONE (SEC_ZONE_BASE_CTL + 2)
#define SEC_ZONE_SO_GET_MAX (SEC_ZONE_SO_GET_ALL_ZONE)

typedef __signed__ char s8;
typedef unsigned char u8;

typedef short s16;
typedef unsigned short u16;

typedef int s32;
typedef unsigned int u32;

typedef long long s64;
typedef unsigned long long u64;

struct st_cmd_if_zone
{
	u8 if_name[IF_NAME_SIZE+1];
	u8 zone_name[ZONE_NAME_LEN+1];
};

struct st_sec_zone {
	u32 id;
        u8  name[ZONE_NAME_LEN+1];
	u32 pri;
        u32 if_num;
        u8 if_name[ZONE_IF_NUM][IF_NAME_SIZE+1];
};

#endif
