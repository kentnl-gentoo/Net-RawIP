/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 *
 */

#ifdef _SOLARIS_
#include "solaris.h"
#else
#include <sys/cdefs.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>


struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t ihl:4;
    u_int8_t version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t	version:4;
    u_int8_t ihl:4;
#else
#error	"Please fix <bytesex.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
  };




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
pkt_send (int fd, unsigned char * sock,u_char *pkt,int size)
{

  if (sendto (fd, (const void *)pkt,size, 0, (const struct sockaddr *) sock, sizeof (struct sockaddr)) < 0)
    {
      perror ("sendto()");
      close (fd);
      exit (-1);
    }
}
