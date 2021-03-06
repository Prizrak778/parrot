/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include "Header.h"



int check_mac_addr(struct ether_header *eh)
{
	if (eh->ether_dhost[0] == DEST_MAC0 &&
	eh->ether_dhost[1] == DEST_MAC1 &&
	eh->ether_dhost[2] == DEST_MAC2 &&
	eh->ether_dhost[3] == DEST_MAC3 &&
	eh->ether_dhost[4] == DEST_MAC4 &&
	eh->ether_dhost[5] == DEST_MAC5)
	{
		return 1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	uint8_t buf[BUF_SIZ];
	int sockfd;
	int sockrecv;
	int ret = -1;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	char sendbuf[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	struct sockaddr_ll socket_address;
	char ifName[IFNAMSIZ];
	ssize_t numbytes;
	
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
	    perror("socket");
	}
	if((sockrecv = init_raw_socket(ifName))<0)
	{
		printf("Fail init raw socket\n");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

	/* Construct the Ethernet header */
	memset(sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = MY_DEST_MAC0;
	eh->ether_dhost[1] = MY_DEST_MAC1;
	eh->ether_dhost[2] = MY_DEST_MAC2;
	eh->ether_dhost[3] = MY_DEST_MAC3;
	eh->ether_dhost[4] = MY_DEST_MAC4;
	eh->ether_dhost[5] = MY_DEST_MAC5;
	/* Ethertype field */
	eh->ether_type = htons(ETH_P_IP);
	tx_len += sizeof(struct ether_header);

	/* Packet data */
	sendbuf[tx_len++] = 0xde;
	sendbuf[tx_len++] = 0xad;
	sendbuf[tx_len++] = 0xbe;
	sendbuf[tx_len++] = 0xef;

	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	socket_address.sll_addr[0] = MY_DEST_MAC0;
	socket_address.sll_addr[1] = MY_DEST_MAC1;
	socket_address.sll_addr[2] = MY_DEST_MAC2;
	socket_address.sll_addr[3] = MY_DEST_MAC3;
	socket_address.sll_addr[4] = MY_DEST_MAC4;
	socket_address.sll_addr[5] = MY_DEST_MAC5;

	/* Header structures */
	eh = (struct ether_header *) buf;
	struct udphdr *udph = (struct udphdr *) (buf + sizeof(struct iphdr) + sizeof(struct ether_header));

	/* Send packet */
	int flag = 1;
	while(1)
	{
		if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
			printf("Send failed\n");
		printf("Send work\n");
		flag = 1;
		while(flag)
		{
			//printf("listener: Waiting to answer...\n");
			numbytes = recvfrom(sockrecv, buf, BUF_SIZ, 0, NULL, NULL);
			//printf("listener: got packet %lu bytes\n", numbytes);
			ret = -1;
			if(check_mac_addr(eh))
			{
				ret = ntohs(udph->len) - sizeof(struct udphdr);
				uint8_t buf_ckeck[] = { 0xde, 0xad, 0xef, 0xbe};
				if(check_message(buf, buf_ckeck))
				{
					/* Print packet */
					printf("Answer data:");
					for (int i=0; i<numbytes; i++)
						printf("%02x:", buf[i]);
					printf("\n");
					flag = 0;
				}
			}
		}
		sleep(1);
	}
	return 0;
}
