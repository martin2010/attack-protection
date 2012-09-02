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

#define IFZONE_DEBUG_CONFIG	1

#ifdef IFZONE_DEBUG_CONFIG
#define dcprintf(x...) printf(x)
#else
#define dcprintf(x...)
#endif

static void printf_help(void)
{
	printf("usage:   ifzone A --append a policy\n"
	       "         ifzone D [no_use] --delete a policy\n"
	       "         ifzone R --modify a policy\n"
	       "         ifzone L --list a policy\n"
	       "         ifzone S [name] --show all or a policy\n"
	       "         ifzone T --set function open/close\n"
	       "         ifzone N --get function state\n"
	       "         ifzone F --flush all policy\n"
	       "         ifzone H --print help information\n\n");

	printf("use:     ifzone A trust 1\n"
	       "         ifzone D trust\n"
	       "         ifzone R trust 2\n"
	       "         ifzone L trust\n"
	       "         ifzone S [trust]\n"
	       "         ifzone T 0/1 (0=open 1=close)\n"
	       "         ifzone N \n"
	       "         ifzone F\n"
	       "         ifzone H\n");

	exit(0);
}

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

	if (argc < 2)
		printf_help();

	c = argv[1][0];
	len = sizeof(struct st_sec_zone);
	i = 4;

	switch (c)
	{
		case 'A':
			if (argc < 4)
				printf_help();

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
			if (argc != 3)
				printf_help();

			strcpy(sec_zone.name, argv[2]);
			if (setsockopt(sockfd, IPPROTO_IP, SEC_ZONE_SO_SET_DEL_ZONE, &sec_zone, len) < 0)
			{
				printf("del sec zone failed!\n");
				return -1;
			}
			break;
		case 'R':
			if (argc < 4)
				printf_help();

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
			if (argc !=3)
				printf_help();

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
			if (argc == 2)
			{
				if (setsockopt(sockfd, IPPROTO_IP, SEC_ZONE_SO_SET_SHOW_ALL_ZONE, &sec_zone, len) < 0)
				{
					printf("Get all sec zone failed!\n");
					ret = -1;
				}
			}
			else if (argc == 3)
			{
				strcpy(sec_zone.name, argv[2]);
				if (setsockopt(sockfd, IPPROTO_IP, SEC_ZONE_SO_SET_SHOW_ZONE, &sec_zone, len) < 0)
				{
					printf("Get sec zone:%s failed!\n", sec_zone.name);
					ret = -1;
				}
			}
			else
				printf_help();
			break;
		case 'F':
			if (argc != 2)
				printf_help();

			if (setsockopt(sockfd, IPPROTO_IP, SEC_ZONE_SO_SET_FLUSH_ALL_ZONE, NULL, 0) < 0)
			{
				printf("Flush all sec zone failed!\n");
				ret = -1;
			}
			break;
		default:
			printf_help();
			break;
	}
	
	return ret;
}

