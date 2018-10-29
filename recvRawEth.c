/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */




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
	int socksend;
	ssize_t numbytes;
	char sendbuf[BUF_SIZ];
	int tx_len = 0;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct ifreq if_ip;	/* get ip addr */
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_storage their_addr;
	struct sockaddr_ll socket_address;
	uint8_t buf[BUF_SIZ];
	char ifName[IFNAMSIZ];
	int flag = 1;
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	if((socksend = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		perror("socket");
	}

	/* Header structures */
	struct ether_header *eh = (struct ether_header *) sendbuf;

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(socksend, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(socksend, SIOCGIFHWADDR, &if_mac) < 0)
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
	eh->ether_dhost[0] = DEST_MAC0;
	eh->ether_dhost[1] = DEST_MAC1;
	eh->ether_dhost[2] = DEST_MAC2;
	eh->ether_dhost[3] = DEST_MAC3;
	eh->ether_dhost[4] = DEST_MAC4;
	eh->ether_dhost[5] = DEST_MAC5;
	/* Ethertype field */
	eh->ether_type = htons(ETH_P_IP);
	tx_len += sizeof(struct ether_header);

	/* Packet data */
	sendbuf[tx_len++] = 0xde;
	sendbuf[tx_len++] = 0xad;
	sendbuf[tx_len++] = 0xef;
	sendbuf[tx_len++] = 0xbe;

	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	socket_address.sll_addr[0] = DEST_MAC0;
	socket_address.sll_addr[1] = DEST_MAC1;
	socket_address.sll_addr[2] = DEST_MAC2;
	socket_address.sll_addr[3] = DEST_MAC3;
	socket_address.sll_addr[4] = DEST_MAC4;
	socket_address.sll_addr[5] = DEST_MAC5;

	memset(&if_ip, 0, sizeof(struct ifreq));

	/* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
	if((sockfd = init_raw_socket(ifName))<0)
	{
		printf("Fail init raw socket\n");
		exit(1);
	}
	eh = (struct ether_header *) buf;
	struct iphdr *iph = (struct iphdr *) (buf + sizeof(struct ether_header));
	struct udphdr *udph = (struct udphdr *) (buf + sizeof(struct iphdr) + sizeof(struct ether_header));
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
				uint8_t buf_ckeck[] = { 0xde, 0xad, 0xbe, 0xef};
				if(check_message(buf, buf_ckeck))
				{
					/* Print packet */
					printf("\tData:");
					for (i=0; i<numbytes; i++)
						printf("%02x:", buf[i]);
					printf("\n");
					if (sendto(socksend, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
						printf("Send failed\n");
					printf("Send work\n");
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
