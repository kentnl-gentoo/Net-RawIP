/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 *
 */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <netinet/ip.h>





unsigned short ip_in_cksum(struct iphdr *iph, unsigned short *ptr, int nbytes)
{

	register long sum = 0;	/* assumes long == 32 bits */
	u_short oddbyte;
	register u_short answer;	/* assumes u_short == 16 bits */
	int pheader_len;
	unsigned short *pheader_ptr;
	
	struct pseudo_header {
		unsigned long saddr;
		unsigned long daddr;
		unsigned char null;
		unsigned char proto;
		unsigned short tlen;
	} pheader;
	
	pheader.saddr = iph->saddr;
	pheader.daddr = iph->daddr;
	pheader.null = 0;
	pheader.proto = iph->protocol;
	pheader.tlen = htons(nbytes);

	pheader_ptr = (unsigned short *)&pheader;
	for (pheader_len = sizeof(pheader); pheader_len; pheader_len -= 2) {
		sum += *pheader_ptr++;
	}
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {	/* mop up an odd byte, if necessary */
		oddbyte = 0;	/* make sure top half is zero */
		*((u_char *) & oddbyte) = *(u_char *) ptr;	/* one byte only */
		sum += oddbyte;
	}
	sum += (sum >> 16);	/* add carry */
	answer = ~sum;		/* ones-complement, then truncate to 16 bits */
	return (answer);
}

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
	register long sum=0;        /* assumes long == 32 bits */
	u_short oddbyte;
	register u_short answer;    /* assumes u_short == 16 bits */
        
	while(nbytes>1){
        	sum+=*ptr++;
	        nbytes-=2;    
	}
	if(nbytes==1){              /* mop up an odd byte, if necessary */
        	oddbyte=0;              /* make sure top half is zero */
	        *((u_char *)&oddbyte)=*(u_char *)ptr;   /* one byte only */
        	sum+=oddbyte;
	}               
	sum+=(sum>>16);             /* add carry */
	answer=~sum;                /* ones-complement, then truncate to 16 bits */
	return(answer);
}

int sprintf_eth_mac(char *b, unsigned char *mac)
{
	return sprintf(b, "%02X:%02X:%02X:%02X:%02X:%02X", 
		       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int print_eth_mac(unsigned char *mac)
{
	char buf[64];
	
	sprintf_eth_mac(buf, mac);
	return printf("%s", buf);
}

int rawsock(void)
{
	int fd,val=1;
    
	if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
			perror("\n(rawsock) Socket problems [fatal]");
		exit(1);
	}  

	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) < 0) {  
        		perror("Cannot set IP_HDRINCL socket option");
		exit(1);
	}
	
	return fd;
}	

struct sockaddr_in *
set_sockaddr (unsigned int  daddr, unsigned short port)
/* Set up target socket address and return pointer to sockaddr_in structure. */
{
  struct sockaddr_in *dest_sockaddr;
  dest_sockaddr = (struct sockaddr_in *) malloc (sizeof (struct sockaddr_in));

  bzero (dest_sockaddr, sizeof (struct sockaddr_in));
  dest_sockaddr->sin_family = AF_INET;
  dest_sockaddr->sin_port = htons (port);
  dest_sockaddr->sin_addr.s_addr = htonl (daddr);
  return (dest_sockaddr);
}

u_long
host_to_ip (char *host_name)
{
  struct hostent *target;
  u_long *resolved_ip;
  resolved_ip = (u_long *) malloc (sizeof (u_long));

  if ((target = gethostbyname (host_name)) == NULL)
    {
      fprintf (stderr, "host_to_ip: %d\n", h_errno);
      exit (-1);
    }
  else
    {
      bcopy (target->h_addr, resolved_ip, sizeof (struct in_addr));
      return ntohl ((u_long) * resolved_ip);
    }
}

void
pkt_send (int fd, struct sockaddr_in * sock,u_char *pkt,size_t size)
{
  if (sendto (fd, (const void *)pkt,size, 0, (const struct sockaddr *) sock, sizeof (struct sockaddr)) < 0)
    {
      perror ("sendto()");
      close (fd);
      exit (-1);
    }
}
