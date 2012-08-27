#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>

#include "packet_attr_cf.h"

static void printf_help(void)
{
	printf("Commands: pa S icmp-fragment 0/1\n"
	       "          pa S icmp-large-packet 0/1\n"
	       "          pa S ip-bad-option 0/1\n"
	       "          pa S ip-unknow-protocol 0/1\n"
	       "          pa S ip-block-frag 0/1\n"
	       "          pa S syn-fragment 0/1\n"
	       "          pa S packet-attr 0/1\n");

	printf("Usage:    pa G icmp-fragment\n"
	       "          pa G icmp-large-packet\n"
	       "          pa G ip-bad-option\n"
	       "          pa G ip-unknow-protocol\n"
	       "          pa G ip-block-frag\n"
	       "          pa G syn-fragment\n"
	       "          pa G packet-attr\n"
	       "          pa G\n");
}


int main(int argc, char *argv[])
{
	char c;
	int flag = 0;
	int command = 0;
	int ret = 0;
	socklen_t len;
	int sockfd;
	int enable_flag;
	struct st_packet_attr pa;

	if (argc < 2)
	{
		printf_help();
		return 0;
	}

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0)
	{
		printf("socket failed!\n");
		return -1;
	}

	c = argv[1][0];

	switch (c)
	{
		case 'S':
			len = sizeof(enable_flag);
			if (argc != 4)
			{
				printf_help();
				break;
			}

                        if (strcmp(argv[2], "icmp-fragment") == 0)
			{
				flag = PACKET_ATTR_SO_SET_ICMP_FRAGMENT_FLAG;
			}
			else if (strcmp(argv[2], "icmp-large-packet") == 0)
			{
				flag = PACKET_ATTR_SO_SET_ICMP_LARGE_PACKET_FLAG;
			}
			else if (strcmp(argv[2], "ip-bad-option") == 0)
			{
				flag = PACKET_ATTR_SO_SET_IP_BAD_OPTION_FLAG;
			}
			else if (strcmp(argv[2], "ip-unknow-protocol") == 0)
			{
				flag = PACKET_ATTR_SO_SET_IP_UNKNOW_PROTOCOL_FLAG;
			}
			else if (strcmp(argv[2], "ip-block-frag") == 0)
			{
				flag = PACKET_ATTR_SO_SET_IP_BLOCK_FRAG_FLAG;
			}
			else if (strcmp(argv[2], "syn-fragment") == 0)
			{
				flag = PACKET_ATTR_SO_SET_SYN_FRAGMENT_FLAG;
			}
			else if (strcmp(argv[2], "packet-attr") == 0)
			{
				flag = PACKET_ATTR_SO_SET_ENABLE_FLAG;
			}
			else
			{
				printf_help();
				break;
			}

			enable_flag = atoi(argv[3]);
			if (enable_flag !=0 && enable_flag != 1)
			{
				printf_help();
				break;
			}

			if (setsockopt(sockfd, IPPROTO_IP, flag, &enable_flag, len) < 0)
			{
				printf("set packet attribute protection failed!\n");
				ret = -1;
			}
			break;
		case 'G':
			if (argc > 3)
			{
				printf_help();
				break;
			}
			

			if (argc == 3 && strcmp(argv[2], "packet-attr") == 0)
			{
				len = sizeof(enable_flag);
				if (getsockopt(sockfd, IPPROTO_IP, PACKET_ATTR_SO_GET_ENABLE_FLAG, &enable_flag, &len) < 0)
				{
					printf("get packet attribute protection failed!\n");
					ret = -1;
					break;
				}
				printf("packet-attr          %d\n", enable_flag);
				break;
			}

			len = sizeof(struct st_packet_attr);
			if (getsockopt(sockfd, IPPROTO_IP, PACKET_ATTR_SO_GET, &pa, &len) < 0)
			{
				printf("get packet attribute protection failed!\n");
				ret = -1;
				break;
			}

			if (argc == 2)
			{
				printf("icmp-fragment         %d\n", pa.icmp_fragment);
				printf("icmp-large-packet     %d\n", pa.icmp_large_packet);
				printf("ip-bad-option         %d\n", pa.ip_bad_option);
				printf("ip-unknow-protocol    %d\n", pa.ip_unknow_protocol);
				printf("ip-block-frag         %d\n", pa.ip_block_frag);
				printf("syn-fragment          %d\n", pa.syn_fragment);
				break;
			}

                        if (strcmp(argv[2], "icmp-fragment") == 0)
			{
				printf("icmp-fragment         %d\n", pa.icmp_fragment);
			}
			else if (strcmp(argv[2], "icmp-large-packet") == 0)
			{
				printf("icmp-large-packet     %d\n", pa.icmp_large_packet);
			}
			else if (strcmp(argv[2], "ip-bad-option") == 0)
			{
				printf("ip-bad-option         %d\n", pa.ip_bad_option);
			}
			else if (strcmp(argv[2], "ip-unknow-protocol") == 0)
			{
				printf("ip-unknow-protocol    %d\n", pa.ip_unknow_protocol);
			}
			else if (strcmp(argv[2], "ip-block-frag") == 0)
			{
				printf("ip-block-frag         %d\n", pa.ip_block_frag);
			}
			else if (strcmp(argv[2], "syn-fragment") == 0)
			{
				printf("syn-fragment          %d\n", pa.syn_fragment);
			}
			else
			{
				printf_help();
			}
	
			break;
		default:
			printf_help();
			break;
	}

	close(sockfd);	
	return ret;
}

