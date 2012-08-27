#ifndef __PACKET_ATTR_CF_H__
#define __PACKET_ATTR_CF_H__ 


#define PACKET_ATTR_BASE_CTL	700
#define PACKET_ATTR_SO_SET_ICMP_FRAGMENT_FLAG (PACKET_ATTR_BASE_CTL)
#define PACKET_ATTR_SO_SET_ICMP_LARGE_PACKET_FLAG (PACKET_ATTR_BASE_CTL + 1)
#define PACKET_ATTR_SO_SET_IP_BAD_OPTION_FLAG (PACKET_ATTR_BASE_CTL + 2)
#define PACKET_ATTR_SO_SET_IP_UNKNOW_PROTOCOL_FLAG (PACKET_ATTR_BASE_CTL + 3)
#define PACKET_ATTR_SO_SET_IP_BLOCK_FRAG_FLAG (PACKET_ATTR_BASE_CTL + 4)
#define PACKET_ATTR_SO_SET_SYN_FRAGMENT_FLAG (PACKET_ATTR_BASE_CTL + 5)
#define PACKET_ATTR_SO_SET_ENABLE_FLAG (PACKET_ATTR_BASE_CTL + 6)
#define PACKET_ATTR_SO_SET_SHOW (PACKET_ATTR_BASE_CTL + 7)
#define PACKET_ATTR_SO_SET_MAX (PACKET_ATTR_SO_SET_SHOW)

#define PACKET_ATTR_SO_GET (PACKET_ATTR_BASE_CTL)
#define PACKET_ATTR_SO_GET_ENABLE_FLAG (PACKET_ATTR_BASE_CTL+1)
#define PACKET_ATTR_SO_GET_MAX (PACKET_ATTR_SO_GET_ENABLE_FLAG)

struct st_packet_attr
{
	unsigned char icmp_fragment;
	unsigned char icmp_large_packet;
	unsigned char ip_bad_option;
	unsigned char ip_unknow_protocol;
	unsigned char ip_block_frag;
	unsigned char syn_fragment;
};


#endif	/* end of __PACKET_ATTR_CF_H__ */
