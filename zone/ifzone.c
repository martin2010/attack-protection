#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>

#include "ifzone.h"

int main(int argc, char *argv[])
{
	char c;
	int i;
	int command = 0;
	int ret = 0;
	socklen_t len;
	int sockfd;
	struct st_sec_zone sec_zone = {0};

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0)
	{
		printf("socket failed!\n");
		return -1;
	}

	c = argv[1][0];
	len = sizeof(struct st_sec_zone);
	i = 4;

	switch (c)
	{
		case 'A':
                        strcpy(sec_zone.name, argv[2]);
			sec_zone.pri = atoll(argv[3]);
			while(argc > i)
			{
				strcpy(sec_zone.if_name[sec_zone.if_num++], argv[i++]);
			}

			if (setsockopt(sockfd, IPPROTO_IP, SEC_ZONE_SO_SET_ADD_ZONE, &sec_zone, len) < 0)
			{
				printf("add sec zone failed!\n");
				return -1;
			}
			break;
		case 'D':
			strcpy(sec_zone.name, argv[2]);
			if (setsockopt(sockfd, IPPROTO_IP, SEC_ZONE_SO_SET_DEL_ZONE, &sec_zone, len) < 0)
			{
				printf("del sec zone failed!\n");
				return -1;
			}
			break;
		case 'R':
                        strcpy(sec_zone.name, argv[2]);
			sec_zone.pri = atoll(argv[3]);
			while(argc > i)
			{
				strcpy(sec_zone.if_name[sec_zone.if_num++], argv[i++]);
			}

			if (setsockopt(sockfd, IPPROTO_IP, SEC_ZONE_SO_SET_MOD_ZONE, &sec_zone, len) < 0)
			{
				printf("modify sec zone failed!\n");
				return -1;
			}
			break;
		case 'L':
			strcpy(sec_zone.name, argv[2]);
			if (getsockopt(sockfd, IPPROTO_IP, SEC_ZONE_SO_GET_ZONE, &sec_zone, &len) < 0)
			{
				printf("get sec zone \"%s\" failed!\n", argv[2]);
				ret = -1;
			}
			else
			{
				
				printf("sec zone name: %s, pri: %-4u",
					sec_zone.name, sec_zone.pri);
				printf("interface: ");
				i = 0;
				while(sec_zone.if_num--)
				{
					printf("%s   ", sec_zone.if_name[i++]);
				}
				printf("\n");
			}
			break;
		case 'S':
			if (argv[2] == NULL)
			{
				if (setsockopt(sockfd, IPPROTO_IP, SEC_ZONE_SO_SET_SHOW_ALL_ZONE, &sec_zone, len) < 0)
				{
					printf("Get all sec zone failed!\n");
					ret = -1;
				}
			}
			else
			{
				strcpy(sec_zone.name, argv[2]);
				if (setsockopt(sockfd, IPPROTO_IP, SEC_ZONE_SO_SET_SHOW_ZONE, &sec_zone, len) < 0)
				{
					printf("Get sec zone:%s failed!\n", sec_zone.name);
					ret = -1;
				}
			}
			break;
		#if 0
		case 'F':
			if (setsockopt(sockfd, IPPROTO_IP, SEC_ZONE_SO_SET_FLUSH_ALL_ZONE, NULL, 0) < 0)
			{
				printf("Flush all sec zone failed!\n");
				ret = -1;
			}
			break;
		#endif
		default:
			break;
	}
	
	return ret;
}

