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
	int command = 0;
	int ret = 0;
	socklen_t len;
	s8 buf[128] = {0};
	int sockfd;
	struct st_cmd_if_zone if_zone = {0};

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0)
	{
		printf("socket failed!\n");
		return -1;
	}

	c = argv[1][0];
	len = sizeof(struct st_cmd_if_zone);

	switch (c)
	{
		case 's':
                        strcpy(if_zone.if_name, argv[2]);
                        strcpy(if_zone.zone_name, argv[3]);

			if (setsockopt(sockfd, IPPROTO_IP, SEC_ZONE_SO_IF_SET_ZONE, &if_zone, len) < 0)
			{
				printf("if set zone failed!\n");
				return -1;
			}
			break;
		case 'g':
			strcpy(if_zone.if_name, argv[2]);
			if (getsockopt(sockfd, IPPROTO_IP, SEC_ZONE_SO_IF_GET_ZONE, &if_zone, &len) < 0)
			{
				printf("if get zone failed!\n");
				return -1;
			}
			printf("interface:%s zone:%s\n", if_zone.if_name, if_zone.zone_name);
			break;
		default:
			break;
	}
	
	return ret;
}

