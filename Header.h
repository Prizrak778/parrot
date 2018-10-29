#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define ETHER_TYPE	0x0800
#define DEFAULT_IF	"eth0"
#define BUF_SIZ		1024
#define LEN_NET     14

#define DEST_MAC0	0x08
#define DEST_MAC1	0x00
#define DEST_MAC2	0x27
#define DEST_MAC3	0x1f
#define DEST_MAC4	0xc0
#define DEST_MAC5	0x37

#define MY_DEST_MAC0	0x8e
#define MY_DEST_MAC1	0x39
#define MY_DEST_MAC2	0xd2
#define MY_DEST_MAC3	0xc9
#define MY_DEST_MAC4	0x31
#define MY_DEST_MAC5	0xe0

int init_raw_socket(char ifName[])
{
	struct ifreq ifopts;	/* set promiscuous mode */
	int sockopt;
	int sockfd;
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1)
	{
		perror("listener: socket");
		return -1;
	}

	/* Set interface to promiscuous mode - do we need to do this every time? */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1)
	{
		perror("setsockopt");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	/* Bind to device */
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ-1) == -1)
	{
		perror("SO_BINDTODEVICE");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	return sockfd;
}

int check_message(uint8_t buf[], uint8_t buf_ckeck[])
{
	int flag = 1;
	//uint8_t buf_ckeck[] = { 0xde, 0xad, 0xbe, 0xef};
	for(int i = 0; i < 4; i++)
	{
		if(buf_ckeck[i] != buf[LEN_NET + i])
		{
			flag = 0;
		}
	}
	return flag;
}
