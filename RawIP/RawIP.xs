#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#ifdef __cplusplus
}
#endif

#include "pcap.h"
#include "netinet/ether.h"
#include "netinet/in.h"
#include "netinet/ip.h"
#include "netinet/tcp.h"

#define TCPHDR 20

#pragma pack(1)
/* typedef struct eipkt {
struct ether_header eh;
struct iphdr ih;
struct tcphdr th; 
} EIPKT; */
typedef struct itpkt {
struct iphdr ih;
struct tcphdr th;
} ITPKT;

unsigned short ip_in_cksum(struct iphdr *iph, unsigned short *ptr, int nbytes);
unsigned short in_cksum(unsigned short *ptr, int nbytes);
int sprintf_eth_mac(char *b, unsigned char *mac);
int print_eth_mac(unsigned char *mac);
int rawsock(void);
struct sockaddr_in *
set_sockaddr (unsigned int  daddr, unsigned short port);
u_long host_to_ip (char *host_name);
void pkt_send(int fd, struct sockaddr_in * sock,u_char *pkt,size_t size);
 
static int
not_here(s)
char *s;
{
    croak("%s not implemented on this architecture", s);
    return -1;
}

static double
constant(name, arg)
char *name;
int arg;
{
    errno = 0;
    switch (*name) {
    case 'A':
	break;
    case 'B':
	break;
    case 'C':
	break;
    case 'D':
	break;
    case 'E':
	break;
    case 'F':
	break;
    case 'G':
	break;
    case 'H':
	break;
    case 'I':
	break;
    case 'J':
	break;
    case 'K':
	break;
    case 'L':
	break;
    case 'M':
	break;
    case 'N':
	break;
    case 'O':
	break;
    case 'P':
	if (strEQ(name, "PCAP_ERRBUF_SIZE"))
#ifdef PCAP_ERRBUF_SIZE
	    return PCAP_ERRBUF_SIZE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "PCAP_VERSION_MAJOR"))
#ifdef PCAP_VERSION_MAJOR
	    return PCAP_VERSION_MAJOR;
#else
	    goto not_there;
#endif
	if (strEQ(name, "PCAP_VERSION_MINOR"))
#ifdef PCAP_VERSION_MINOR
	    return PCAP_VERSION_MINOR;
#else
	    goto not_there;
#endif
	break;
    case 'Q':
	break;
    case 'R':
	break;
    case 'S':
	break;
    case 'T':
	break;
    case 'U':
	break;
    case 'V':
	break;
    case 'W':
	break;
    case 'X':
	break;
    case 'Y':
	break;
    case 'Z':
	break;
    case 'a':
	break;
    case 'b':
	break;
    case 'c':
	break;
    case 'd':
	break;
    case 'e':
	break;
    case 'f':
	break;
    case 'g':
	break;
    case 'h':
	break;
    case 'i':
	break;
    case 'j':
	break;
    case 'k':
	break;
    case 'l':
	if (strEQ(name, "lib_pcap_h"))
#ifdef lib_pcap_h
	    return lib_pcap_h;
#else
	    goto not_there;
#endif
	break;
    case 'm':
	break;
    case 'n':
	break;
    case 'o':
	break;
    case 'p':
	break;
    case 'q':
	break;
    case 'r':
	break;
    case 's':
	break;
    case 't':
	break;
    case 'u':
	break;
    case 'v':
	break;
    case 'w':
	break;
    case 'x':
	break;
    case 'y':
	break;
    case 'z':
	break;
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

SV * (*ptr)(u_char*);
ITPKT *pit;

static SV * retref (ref)
     u_char * ref;
    {
    return (SV*)ref;
    }

static SV * handler (file)
    u_char * file;
    {
    SV * handle; 
    GV * gv;
    handle = sv_newmortal();
    gv = newGVgen("Net::RawIP");
    do_open(gv, "+<&", 3, FALSE, 0, 0, (FILE*)file);
    sv_setsv(handle, sv_bless(newRV_noinc((SV*)gv), gv_stashpv("Net::RawIP",1)));
    return handle;
    }


MODULE = Net::RawIP		PACKAGE = Net::RawIP      PREFIX = pcap_

PROTOTYPES: ENABLE


double
constant(name,arg)
        char *        name
	int           arg

unsigned int 
rawsock()

struct sockaddr_in *
set_sockaddr (daddr,port)
unsigned int daddr
unsigned short port

unsigned long
host_to_ip (host_name)
char *host_name

void 
pkt_send (fd,sock,pkt)
int fd
struct sockaddr_in * sock
SV *pkt
CODE:
  pkt_send (fd,sock,SvPV(pkt,na),SvCUR(pkt));

AV * 
tcp_pkt_parse(pkt)
  SV * pkt
CODE:
  AV * flags;
  u_char * c;
  ITPKT *pktr;
  pktr = (ITPKT *)SvPV(pkt,na);
  RETVAL = newAV();
  sv_2mortal((SV*)RETVAL);
  av_unshift(RETVAL,28);
 /*  c = (u_char*)pktr->eh.ether_dhost;
  av_store(RETVAL,0,
  newSVpvf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",c[0],c[1],c[2],c[3],c[4],c[5]));
  c = (u_char*)pktr->eh.ether_shost;
  av_store(RETVAL,1,
  newSVpvf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",c[0],c[1],c[2],c[3],c[4],c[5]));
  av_store(RETVAL,2,newSViv(ntohs(pktr->eh.ether_type))); */ 
  av_store(RETVAL,0,newSViv(pktr->ih.version));
  av_store(RETVAL,1,newSViv(pktr->ih.ihl));
  av_store(RETVAL,2,newSViv(pktr->ih.tos));
  av_store(RETVAL,3,newSViv(ntohs(pktr->ih.tot_len)));
  av_store(RETVAL,4,newSViv(ntohs(pktr->ih.id)));
  av_store(RETVAL,5,newSViv(ntohs(pktr->ih.frag_off)));
  av_store(RETVAL,6,newSViv(pktr->ih.ttl));
  av_store(RETVAL,7,newSViv(pktr->ih.protocol));
  av_store(RETVAL,8,newSViv(ntohs(pktr->ih.check)));
  av_store(RETVAL,9,newSViv(ntohl(pktr->ih.saddr)));
  av_store(RETVAL,10,newSViv(ntohl(pktr->ih.daddr)));
  av_store(RETVAL,11,newSViv(ntohs(pktr->th.source)));
  av_store(RETVAL,12,newSViv(ntohs(pktr->th.dest)));
  av_store(RETVAL,13,newSViv(ntohl(pktr->th.seq)));
  av_store(RETVAL,14,newSViv(ntohl(pktr->th.ack_seq)));
  av_store(RETVAL,15,newSViv(pktr->th.doff));
  av_store(RETVAL,16,newSViv(pktr->th.res1));
  av_store(RETVAL,17,newSViv(pktr->th.res2));
  av_store(RETVAL,18,newSViv(pktr->th.urg));
  av_store(RETVAL,19,newSViv(pktr->th.ack));
  av_store(RETVAL,20,newSViv(pktr->th.psh));
  av_store(RETVAL,21,newSViv(pktr->th.rst));
  av_store(RETVAL,22,newSViv(pktr->th.syn));
  av_store(RETVAL,23,newSViv(pktr->th.fin));
  av_store(RETVAL,24,newSViv(ntohs(pktr->th.window)));
  av_store(RETVAL,25,newSViv(ntohs(pktr->th.check)));
  av_store(RETVAL,26,newSViv(ntohs(pktr->th.urg_ptr)));
  av_store(RETVAL,27,newSVpv(((u_char*)&pktr->th.urg_ptr+2),
  (u_int)ntohs(pktr->ih.tot_len) - (4*pktr->ih.ihl + TCPHDR)));
OUTPUT:
RETVAL

SV *
tcp_pkt_creat(p)
  SV * p
CODE:
   AV * pkt;
   New(601,pit,1,ITPKT);
   if(SvTYPE(SvRV(p)) == SVt_PVAV) pkt = (AV *)SvRV(p);
   else
   croak("Not array reference\n");
   pit->ih.version = SvIV(*av_fetch(pkt,0,0));
   pit->ih.ihl = SvIV(*av_fetch(pkt,1,0));
   pit->ih.tos = SvIV(*av_fetch(pkt,2,0));
   pit->ih.tot_len = htons(SvIV(*av_fetch(pkt,3,0)));
   if(!pit->ih.tot_len)
   pit->ih.tot_len = htons(4*pit->ih.ihl + TCPHDR + SvCUR(*av_fetch(pkt,27,0))); 
   pit->ih.id = htons(SvIV(*av_fetch(pkt,4,0)));
   pit->ih.frag_off = htons(SvIV(*av_fetch(pkt,5,0)));
   pit->ih.ttl = SvIV(*av_fetch(pkt,6,0));
   pit->ih.protocol = SvIV(*av_fetch(pkt,7,0));
   pit->ih.check = htons(SvIV(*av_fetch(pkt,8,0)));
   pit->ih.saddr = htonl(SvIV(*av_fetch(pkt,9,0)));
   pit->ih.daddr = htonl(SvIV(*av_fetch(pkt,10,0)));
   if(!pit->ih.check) pit->ih.check = in_cksum((unsigned short *)pit,4*pit->ih.ihl); 
   pit->th.source = htons(SvIV(*av_fetch(pkt,11,0)));
   pit->th.dest = htons(SvIV(*av_fetch(pkt,12,0)));
   pit->th.seq = htonl(SvIV(*av_fetch(pkt,13,0)));
   pit->th.ack_seq = htonl(SvIV(*av_fetch(pkt,14,0)));
   pit->th.doff = SvIV(*av_fetch(pkt,15,0));
   pit->th.res1 = SvIV(*av_fetch(pkt,16,0));
   pit->th.res2 = SvIV(*av_fetch(pkt,17,0));
   pit->th.urg = SvIV(*av_fetch(pkt,18,0));
   pit->th.ack = SvIV(*av_fetch(pkt,19,0));
   pit->th.psh = SvIV(*av_fetch(pkt,20,0));
   pit->th.rst = SvIV(*av_fetch(pkt,21,0));
   pit->th.syn = SvIV(*av_fetch(pkt,22,0));
   pit->th.fin = SvIV(*av_fetch(pkt,23,0));
   pit->th.window = htons(SvIV(*av_fetch(pkt,24,0)));
   pit->th.check = htons(SvIV(*av_fetch(pkt,25,0)));
   pit->th.urg_ptr = htons(SvIV(*av_fetch(pkt,26,0)));
   RETVAL = newSVpv((u_char*)pit,sizeof(ITPKT));
   sv_catsv(RETVAL,*av_fetch(pkt,27,0));
   if(!pit->th.check) {
   pit = (ITPKT*)SvPV(RETVAL,na);
   pit->th.check = ip_in_cksum((struct iphdr *)pit,(unsigned short *)&(pit->th),
   sizeof(struct tcphdr) + SvCUR(*av_fetch(pkt,27,0)));
   sv_setpvn(RETVAL,(u_char*)pit,sizeof(ITPKT)+SvCUR(*av_fetch(pkt,27,0)));
   }
OUTPUT:
RETVAL  

pcap_t *
open_live(device,snaplen,promisc,to_ms,ebuf)
     char *device
     int snaplen
     int promisc
     int to_ms
     char * ebuf
CODE:
     ebuf = (char*)safemalloc(PCAP_ERRBUF_SIZE);
     RETVAL = pcap_open_live(device,snaplen,promisc,to_ms,ebuf);     
     Safefree(ebuf);
OUTPUT:
ebuf
RETVAL

pcap_t *
open_offline(fname,ebuf)
     char *fname
     char *ebuf
CODE:
     ebuf = (char*)safemalloc(PCAP_ERRBUF_SIZE);
     RETVAL = pcap_open_offline(fname,ebuf);
     Safefree(ebuf);
OUTPUT:
ebuf
RETVAL

SV *
pcap_dump_open(p,fname)
     pcap_t *p
     char *fname
CODE:
   RETVAL = newSViv((u_int)pcap_dump_open(p,fname));
OUTPUT:
RETVAL

char *
lookupdev(ebuf)
     char *ebuf
CODE:
     ebuf = (char*)safemalloc(PCAP_ERRBUF_SIZE);
     RETVAL = pcap_lookupdev(ebuf);
     Safefree(ebuf);
OUTPUT:
ebuf
RETVAL
        
int 
lookupnet(device,netp,maskp,ebuf)
    char *device
    bpf_u_int32 netp
    bpf_u_int32 maskp
    char *ebuf
CODE:
     ebuf = (char*)safemalloc(PCAP_ERRBUF_SIZE);
     RETVAL = pcap_lookupnet(device,&netp,&maskp,ebuf);
     Safefree(ebuf);
OUTPUT:
ebuf
RETVAL

void
dump(ptr,pkt,user)
  SV * ptr
  SV * pkt
  SV * user
CODE:
pcap_dump((u_char*)IoOFP(sv_2io(ptr)),
          (struct pcap_pkthdr*)(SvPV(pkt,na)),
          (u_char*)(SvPV(user,na)));      

int 
dispatch(p,cnt,printer,user)
    pcap_t *p
    int cnt
    pcap_handler printer
    SV * user
CODE:
    static  void
    call_printer (file,pkt,user)
    u_char * file;
    struct pcap_pkthdr * pkt;
    u_char * user;
    {
    dSP ;
    PUSHMARK(sp) ;
    XPUSHs(sv_2mortal(newSVsv(ptr(file))));
    XPUSHs(sv_2mortal(newSVpv((u_char *)pkt,sizeof(struct pcap_pkthdr))));
    XPUSHs(sv_2mortal(newSVpv(user,pkt->caplen)));
    PUTBACK ;
    perl_call_sv((SV*)printer,G_VOID);
    }
    if(!SvROK(user) && SvOK(user)){
    (u_char *)user = SvIV(user); 
    ptr = &handler;
    }
    else {
    ptr = &retref;
    }
    RETVAL = pcap_dispatch(p,cnt,(pcap_handler)&call_printer,(u_char*)user);
OUTPUT:
RETVAL

int 
loop(p,cnt,printer,user)
    pcap_t *p
    int cnt
    pcap_handler printer
    SV *user
CODE:
    static  void
    call_printer (file,pkt,user)
    u_char * file;
    struct pcap_pkthdr * pkt;
    u_char * user;
    {
    dSP ;
    PUSHMARK(sp) ;
    XPUSHs(sv_2mortal(newSVsv(ptr(file))));
    XPUSHs(sv_2mortal(newSVpv((u_char *)pkt,sizeof(struct pcap_pkthdr))));
    XPUSHs(sv_2mortal(newSVpv(user,pkt->caplen)));
    PUTBACK ;
    perl_call_sv((SV*)printer,G_VOID);
    }
    if(!SvROK(user) && SvOK(user)){
    (u_char *)user = SvIV(user); 
    ptr = &handler;
    }
    else {
    ptr = &retref;
    }
    RETVAL = pcap_loop(p,cnt,(pcap_handler)&call_printer,(u_char*)user);
OUTPUT:
RETVAL

   
int 
compile(p,fp,str,optimize,netmask)
    pcap_t * p
    struct bpf_program *fp
    char *str
    int optimize
    unsigned int netmask
CODE:
    fp = (struct bpf_program *)safemalloc(sizeof(struct bpf_program));
    RETVAL = pcap_compile(p,fp,str,optimize,netmask);
OUTPUT: 
fp
RETVAL
      
int 
pcap_setfilter(p,fp)
   pcap_t *p
   struct bpf_program *fp
OUTPUT:
RETVAL

SV *
next(p,h)
   pcap_t *p      
   SV *h
CODE:
   STRLEN len;
   u_char * hdr;
   const u_char * next;
   len = sizeof(struct pcap_pkthdr);
   if(!SvOK(h)){
   sv_setpv(h,"new");
   SvGROW(h,len) ;
   }
   hdr = (u_char *)SvPV(h,len) ;
   next = pcap_next(p,(struct pcap_pkthdr*)hdr);
   RETVAL = newSVpv((u_char *)next,((struct pcap_pkthdr*)hdr)->caplen);
   sv_setpvn(h,hdr,len);
OUTPUT:
h
RETVAL



int 
pcap_datalink(p)  
   pcap_t *p 
OUTPUT:
RETVAL

int 
pcap_snapshot(p)  
   pcap_t *p 
OUTPUT:
RETVAL

int 
pcap_is_swapped(p)  
   pcap_t *p 
OUTPUT:
RETVAL

int 
pcap_major_version(p)  
   pcap_t *p 
OUTPUT:
RETVAL

int 
pcap_minor_version(p)  
   pcap_t *p 
OUTPUT:
RETVAL

int 
stat(p,ps)  
   pcap_t *p
   u_char *ps 
CODE:
  ps = safemalloc(sizeof(struct pcap_stat));
  RETVAL = pcap_stats(p,(struct pcap_stat*)ps);
  Safefree(ps);
OUTPUT:
ps
RETVAL
       	

int 
pcap_fileno(p)
pcap_t *p
OUTPUT:
RETVAL


void 
pcap_perror(p,prefix) 
   pcap_t *p
   char *prefix 

SV *
pcap_geterr(p)
   pcap_t *p
CODE:
   RETVAL = newSVpv(pcap_geterr(p),0);   
OUTPUT:
RETVAL


SV *
pcap_strerror(error) 
   int error    
CODE:
   RETVAL = newSVpv(pcap_strerror(error),0);   
OUTPUT:
RETVAL

void 
pcap_close(p) 
  pcap_t *p
  
  
void 
pcap_dump_close(p) 
  pcap_dumper_t *p 



FILE *
pcap_file(p)
   pcap_t *p
OUTPUT:
RETVAL
              	                					