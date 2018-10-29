/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */


#include <linux/ip.h>
#include <linux/udp.h>

#include "Header.h"

//MAC addr: lo
#define DEST_MAC0	0x00
#define DEST_MAC1	0x00
#define DEST_MAC2	0x00
#define DEST_MAC3	0x00
#define DEST_MAC4	0x00
#define DEST_MAC5	0x01





int check_mac_addr(struct ether_header *eh)
{
	if (eh->ether_dhost[0] == DEST_MAC0 &&
	eh->ether_dhost[1] == DEST_MAC1 &&
	eh->ether_dhost[2] == DEST_MAC2 &&
	eh->ether_dhost[3] == DEST_MAC3 &&
	eh->ether_dhost[4] == DEST_MAC4 &&
	eh->ether_dhost[5] == DEST_MAC5)
	{
		printf("Correct destination MAC address\n");
		return 1;
	}
	else
	{
		printf("Wrong destination MAC: %x:%x:%x:%x:%x:%x\n",
		eh->ether_dhost[0],
		eh->ether_dhost[1],
		eh->ether_dhost[2],
		eh->ether_dhost[3],
		eh->ether_dhost[4],
		eh->ether_dhost[5]);
		return 0;
	}
}


int main(int argc, char *argv[])
{
	char sender[INET6_ADDRSTRLEN];
	int sockfd, ret, i;
	int sockopt;
	ssize_t numbytes;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct ifreq if_ip;	/* get ip addr */
	struct sockaddr_storage their_addr;
	uint8_t buf[BUF_SIZ];
	char ifName[IFNAMSIZ];
	int flag = 1;
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Header structures */
	struct ether_header *eh = (struct ether_header *) buf;
	struct iphdr *iph = (struct iphdr *) (buf + sizeof(struct ether_header));
	struct udphdr *udph = (struct udphdr *) (buf + sizeof(struct iphdr) + sizeof(struct ether_header));

	memset(&if_ip, 0, sizeof(struct ifreq));

	/* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
	if((sockfd = init_raw_socket(ifName))<0)
	{
		printf("Fail init raw socket\n");
		exit(1);
	}
	while(1)
	{
		flag = 1;
		printf("listener: Waiting to recvfrom...\n");
		numbytes = recvfrom(sockfd, buf, BUF_SIZ, 0, NULL, NULL);
		printf("listener: got packet %lu bytes\n", numbytes);

		/* Check the packet is for me */
		if(check_mac_addr(eh))
		{
			ret = -1;
			/* Get source IP */
			((struct sockaddr_in *)&their_addr)->sin_addr.s_addr = iph->saddr;
			inet_ntop(AF_INET, &((struct sockaddr_in*)&their_addr)->sin_addr, sender, sizeof sender);

			/* Look up my device IP addr if possible */
			strncpy(if_ip.ifr_name, ifName, IFNAMSIZ - 1);
			if (ioctl(sockfd, SIOCGIFADDR, &if_ip) >= 0)
			{ /* if we can't check then don't */
				printf("Source IP: %s\n My IP: %s\n", sender,
				inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr));
				/* ignore if I sent it */
				if (strcmp(sender, inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr)) == 0)
				{
					printf("but I sent it :(\n");
					ret = -1;
					flag = 0;
				}
			}
			if(flag)
			{
				/* UDP payload length */
				/* Проверка на ключевое слово*/
				ret = ntohs(udph->len) - sizeof(struct udphdr);
				if(check_message(buf))
				{
					/* Print packet */
					printf("\tData:");
					for (i=0; i<numbytes; i++)
						printf("%02x:", buf[i]);
					printf("\n");
				}
				else
				{
					printf("Wrong key\n");
				}
			}
		}
	}
	close(sockfd);
	return ret;
}
