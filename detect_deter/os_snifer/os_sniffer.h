#ifndef __OS_SNIFFER_H__
#define __OS_SNIFFER_H__

#define  OS_SNIFFER_BASE_CTL					346

#define OS_SNIFFER_SO_SET_SYN_FIN				OS_SNIFFER_BASE_CTL
#define OS_SNIFFER_SO_SET_FIN_NO_ACK		 		OS_SNIFFER_BASE_CTL+1
#define OS_SNIFFER_SO_SET_TCP_NO_FLAG	 			OS_SNIFFER_BASE_CTL+2
#define OS_SNIFFER_SO_SET_MAX					OS_SNIFFER_SO_SET_TCP_NO_FLAG


#define OS_SNIFFER_SO_GET_SYN_FIN				OS_SNIFFER_BASE_CTL
#define OS_SNIFFER_SO_GET_FIN_NO_ACK				OS_SNIFFER_BASE_CTL+1
#define OS_SNIFFER_SO_GET_TCP_NO_FLAG				OS_SNIFFER_BASE_CTL+2
#define OS_SNIFFER_SO_GET_MAX					OS_SNIFFER_SO_GET_TCP_NO_FLAG

struct st_cmd_os_sniffer
{
	u8 zone_name[PF_NAME_LEN+1];
	bool flag;
};

#endif //end of __OS_SNIFFER_H__

