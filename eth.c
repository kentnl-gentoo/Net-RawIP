/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 *
 */

#include <sys/uio.h>
#include <stdio.h>
#include <sys/ioctl.h>

#ifdef  _GLIBC_

#include <net/if_packet.h>
#include <netinet/if_ether.h>
#include <net/if.h>

#else 

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>

#endif


											
int send_eth_packet(int fd,char* eth_device,u_char *pkt,int len)
{
	int retval;
        struct msghdr msg;
	struct sockaddr_pkt spkt;
	struct iovec iov;
	strcpy(spkt.spkt_device, eth_device);
	spkt.spkt_protocol = htons(ETH_P_IP);
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &spkt;
	msg.msg_namelen = sizeof(spkt);
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_base = pkt;
	iov.iov_len = len;

	retval = sendmsg(fd, &msg, 0);
	if (retval < 0)
		fprintf(stderr, "sendmsg retval = %d \n", retval);
	return retval;
}

int mac_disc(unsigned int addr,unsigned char * eth_mac){

struct arpreq
  {
    struct sockaddr arp_pa;		/* Protocol address.  */
    struct sockaddr arp_ha;		/* Hardware address.  */
    int arp_flags;			/* Flags.  */
    struct sockaddr arp_netmask;	/* Netmask (only for proxy arps).  */
    char arp_dev[16];
  } req;

int fd;
fd = socket(AF_INET,SOCK_DGRAM,0);
memset((char*)&req,0,sizeof(req));
req.arp_pa.sa_family = AF_INET;
*(unsigned int*)(req.arp_pa.sa_data+2) = htonl(addr);
if(ioctl(fd,SIOCGARP,&req) < 0){
close(fd);
return 0;
}
memcpy(eth_mac, req.arp_ha.sa_data, ETH_ALEN);
close(fd);
return 1;
}

int
tap(char *dev,int mode,unsigned int *my_eth_ip,unsigned char *my_eth_mac)
{
	
	int fd;				
	struct ifreq ifr;   /* Link-layer interface request structure */
        	            /* Ethernet code for IP 0x0800==ETH_P_IP */
	if ((fd = socket(AF_INET, SOCK_PACKET, 
			/*htons(ETH_P_IP)*/ htons(ETH_P_ALL))) < 0) {
			perror("(tap) SOCK_PACKET allocation problems [fatal]");
	        exit(1);					           
	}
	strcpy(ifr.ifr_name, dev);				
	if ((ioctl(fd, SIOCGIFFLAGS, &ifr)) < 0) {    /* Get the device info */
			perror("(tap) Can't get device flags [fatal]");
	        close(fd);
      		exit(1);
	}
	if (!mode)
		ifr.ifr_flags &= ~IFF_PROMISC;    /* Unset promiscuous mode */
	else
		ifr.ifr_flags |= IFF_PROMISC;        /* Set promiscuous mode */
	if ((ioctl(fd, SIOCSIFFLAGS, &ifr)) < 0) {    /* Set flags */
			perror("(tap) Can't set/unset promiscuous mode [fatal]");
		close(fd);
		exit(1);
	}
	if(!mode){
        	close(fd);
	        return 0;
	} else {
		if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
				perror("(tap) Can't get interface IP address");
			tap(dev,0,0,0);
			exit(1);
		}
		*my_eth_ip = ntohl(*(unsigned int *) (ifr.ifr_addr.sa_data + 2));
		if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
				perror("(tap) Can't get interface HW address");
			tap(dev, 0,0,0);
			exit(1);
		}
		memcpy(my_eth_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
		return fd;
	}
}
