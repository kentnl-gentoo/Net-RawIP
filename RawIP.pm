package Net::RawIP::iphdr;
use Class::Struct qw(struct);
my @iphdr = qw(version ihl tos tot_len id frag_off ttl protocol check saddr 
daddr);
struct ( 'Net::RawIP::iphdr' => [ map { $_ => '$' } @iphdr ] );

package Net::RawIP::tcphdr;
use Class::Struct qw(struct);
my @tcphdr = qw(source dest seq ack_seq doff res1 res2 urg ack psh rst syn
fin window check urg_ptr data);
struct ( 'Net::RawIP::tcphdr' => [map { $_ => '$' } @tcphdr ] );

package Net::RawIP::udphdr;
use Class::Struct qw(struct);
my @udphdr = qw(source dest len check data);
struct ( 'Net::RawIP::udphdr' => [map { $_ => '$' } @udphdr ] );

package Net::RawIP::icmphdr;
use Class::Struct qw(struct);
my @icmphdr = qw(type code check gateway id sequence unused mtu data);
struct ( 'Net::RawIP::icmphdr' => [map { $_ => '$' } @icmphdr ] );

package Net::RawIP::generichdr;
use Class::Struct qw(struct);
my @generichdr = qw(data);
struct ( 'Net::RawIP::generichdr' => [map { $_ => '$' } @generichdr ] );

package Net::RawIP::opt;
use Class::Struct qw(struct);
my @opt = qw(type len data);
struct ( 'Net::RawIP::opt' => [map { $_ => '@' } @opt ] );

package Net::RawIP::ethhdr;
use Class::Struct qw(struct);
my @ethhdr = qw(dest source proto);
struct ( 'Net::RawIP::ethhdr' => [map { $_ => '$' } @ethhdr ] );

package Net::RawIP;
use Carp;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD);
require Exporter;
require DynaLoader;
require AutoLoader;
@ISA = qw(Exporter DynaLoader);

@EXPORT = qw(timem open_live dump_open dispatch dump loop);
@EXPORT_OK = qw(
PCAP_ERRBUF_SIZE PCAP_VERSION_MAJOR PCAP_VERSION_MINOR lib_pcap_h
open_live open_offline dump_open lookupdev lookupnet dispatch
loop dump compile setfilter next datalink snapshot is_swapped major_version
minor_version stats file fileno perror geterr strerror close dump_close);  
%EXPORT_TAGS = ( 'pcap' => [
qw(
PCAP_ERRBUF_SIZE PCAP_VERSION_MAJOR PCAP_VERSION_MINOR lib_pcap_h
open_live open_offline dump_open lookupdev lookupnet dispatch
loop dump compile setfilter next datalink snapshot is_swapped major_version
minor_version stats file fileno perror geterr strerror close dump_close timem)  
                            ]
	       );	  	    

$VERSION = '0.04';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "& not defined" if $constname eq 'constant';
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
	if ($! =~ /Invalid/) {
	    $AutoLoader::AUTOLOAD = $AUTOLOAD;
	    goto &AutoLoader::AUTOLOAD;
	}
	else {
		croak "Your vendor has not defined Net::RawIP macro $constname";
	}
    }
    *$AUTOLOAD = sub () { $val };
    goto &$AUTOLOAD;
}
bootstrap Net::RawIP $VERSION;
die "Must have euid = 0 for use Net::RawIP" if $>;

$^W = 0;

sub new {
 my ($proto,$ref) = @_;
 my $class = ref($proto) || $proto;
 my $self = {};
 bless $self,$class;
 $self->proto($ref);
 $self->_unpack($ref);;
 return $self
}

sub proto {
 my ($class,$args) = @_;
 my @proto = qw(tcp udp icmp generic);
 my $proto;
 unless ($class->{'proto'}){
 map {$proto = $_ if exists $args->{$_} } @proto;
 $proto = 'tcp' unless $proto;
 $class->{'proto'} = $proto;
 }
 return $class->{'proto'}
}

sub optset {
 my($class,%arg) = @_;
 my %n = ('tcp',17,'udp',5,'icmp',9,'generic',1); 
 my $optproto;
 my $i;
 my $len;
 map {
    my @array;
    $optproto = $_;
    $class->{"opts$optproto"} = new Net::RawIP::opt 
                                           unless $class->{"opts$optproto"};
    @{$class->{"opts$optproto"}->type} = ();
    @{$class->{"opts$optproto"}->len} = ();
    @{$class->{"opts$optproto"}->data} = ();
    map {
     @{$class->{"opts$optproto"}->$_()} = @{${$arg{$optproto}}{$_}};
        } 
    keys %{$arg{$optproto}};
      $i = 0;
    map {
$len = length($class->{"opts$optproto"}->data($i));
$len = 38 if $len > 38;
$class->{"opts$optproto"}->len($i,2+$len);
        $i++
        }
     @{${$arg{$optproto}}{'data'}};
    $i = 0;
    map { 
    push @array,
    ($_,$class->{"opts$optproto"}->len($i),$class->{"opts$optproto"}->data($i));
    $i++;
     } @{$class->{"opts$optproto"}->type}; 
    $i = 0;
    if($optproto eq 'tcp'){
    $i = 1;
    ${$class->{'tcphdr'}}[17] = 0 unless defined ${$class->{'tcphdr'}}[17];
    } 
    ${$class->{"$class->{'proto'}hdr"}}[$i+$n{$class->{'proto'}}] = [(@array)]
 } sort keys %arg;
$class->_pack(1);
}

sub optget {
my($class,%arg) = @_;
my @array;
my $optproto;
my $i = 0;
my $type;
my %n = ('tcp',17,'udp',5,'icmp',9,'generic',1);
map {
  $optproto = $_;
  if(!exists ${$arg{"$optproto"}}{'type'}){
  if($optproto eq 'tcp'){$i = 1}
  push @array,
    (@{${$class->{"$class->{'proto'}hdr"}}[$i+$n{$class->{'proto'}}]});
  }
  else 
  {
    $i = 0;
  map {
    $type = $_;
    $i = 0; 
    map {
       if($type == $_){
  push @array,($class->{"opts$optproto"}->type($i));       
  push @array,($class->{"opts$optproto"}->len($i));       
  push @array,($class->{"opts$optproto"}->data($i));       
       }
     $i++;
     } @{$class->{"opts$optproto"}->type()};
   } @{${$arg{"$optproto"}}{'type'}};
  } 
    } sort keys %arg;
return (@array)
}

sub optunset {
my($class,@arg) = @_;
my @array;
my $optproto;
my $i = 0;
my %n = ('tcp',17,'udp',5,'icmp',9,'generic',1);
map {
  $optproto = $_;
  if($optproto eq 'tcp'){
  $i = 1;
  $class->{'tcphdr'}->doff(5);
  }
  else 
  {
  $class->{'iphdr'}->ihl(5);
  }
  $class->{"opts$optproto"} = 0;
  ${$class->{"$class->{'proto'}hdr"}}[$i+$n{$class->{'proto'}}] = 0;
    } sort @arg;
$class->_pack(1);
}

sub ethnew {
 my($class,$dev,@arg) = @_;
 my($ip,$mac);
 $class->{'ethhdr'} = new Net::RawIP::ethhdr; 
 $class->{'tap'} = tap($dev,1,$ip,$mac);
 $class->{'ethdev'} = $dev;
 $class->{'ethmac'} = $mac;
 $class->{'ethip'} = $ip; 
 $class->{'ethhdr'}->dest($mac);
 $class->{'ethhdr'}->source($mac); 
 my $ipproto = pack ("n1",0x0800);
 $class->{'ethpack'}=$class->{'ethhdr'}->dest
                    .$class->{'ethhdr'}->source
		    .$ipproto;
 $class->ethset(@arg) if @arg;
}

sub ethset {
 my($self,%hash) = @_;
 map { $self->{'ethhdr'}->$_($hash{$_}) } keys %hash;
 my $source = $self->{'ethhdr'}->source;
 my $dest = $self->{'ethhdr'}->dest;
 
 if ($source =~ /^(\w\w):(\w\w):(\w\w):(\w\w):(\w\w):(\w\w)$/)
 {
 $self->{'ethhdr'}->source(
                     pack("C6",hex($1),hex($2),hex($3),hex($4),hex($5),hex($6))
	                  );
 $source = $self->{'ethhdr'}->source;
 }

 if ($dest =~ /^(\w\w):(\w\w):(\w\w):(\w\w):(\w\w):(\w\w)$/)
 {
 $self->{'ethhdr'}->dest(
                     pack("C6",hex($1),hex($2),hex($3),hex($4),hex($5),hex($6))
		        );
 $dest = $self->{'ethhdr'}->dest;
 }
 
 $self->{'ethhdr'}->source(mac(host_to_ip($source)))
 unless($source =~ /[^A-Za-z0-9\-.]/ && length($source) == 6);
 $self->{'ethhdr'}->dest(mac(host_to_ip($dest)))
 unless($dest =~ /[^A-Za-z0-9\-.]/ && length($dest) == 6);
 my $ipproto = pack ("n1",0x0800);
 $self->{'ethpack'}=$self->{'ethhdr'}->dest.$self->{'ethhdr'}->source.$ipproto;
}

sub mac {
 my $ip = $_[0];
 my $mac;
 my $obj;
    if(mac_disc($ip,$mac)){
    return $mac;
    }
    else{
    $obj = new Net::RawIP ({ip => {saddr => 0,
                                   daddr => $ip},
			    icmp => {}
			  });
    $obj->send;
        if(mac_disc($ip,$mac)){
         return $mac;
        }
        else {
	my $ipn = sprintf("%u.%u.%u.%u",unpack("C4",pack("N1",$ip)));
	die "Can't discovery mac address for $ipn";
	}
    }
}

sub ethsend {
my ($self,$delay,$times) = @_;
if(!$times){
$times = 1;
}
while($times){
send_eth_packet($self->{tap},$self->{'ethdev'},
           $self->{'ethpack'}.$self->{'pack'});
sleep $delay;
$times--
}
} 


sub _unpack {
 my ($self,$ref) = @_;
 $self->{'iphdr'} = new Net::RawIP::iphdr;
 eval '$self->{'."$self->{'proto'}".'hdr} = new Net::RawIP::'."$self->{'proto'}".'hdr';
 eval '$self->'."$self->{'proto'}_default"; 
 $self->set($ref);
}

sub tcp_default {
my ($class) = @_;
@{$class->{'iphdr'}} = (4,5,16,0,0,0x4000,64,6,0,0,0);
@{$class->{'tcphdr'}} = (0,0,0,0,5,0,0,0,0,0,0,0,0,0xffff,0,0,'');
}

sub udp_default {
my ($class) = @_;
@{$class->{'iphdr'}} = (4,5,16,0,0,0x4000,64,17,0,0,0);
@{$class->{'udphdr'}} = (0,0,0,0,'');
}

sub icmp_default {
my ($class) = @_;
@{$class->{'iphdr'}} = (4,5,16,0,0,0x4000,64,1,0,0,0); 	       
@{$class->{'icmphdr'}} = (0,0,0,0,0,0,0,0,'');
}

sub generic_default {
my ($class) = @_;
@{$class->{'iphdr'}} = (4,5,16,0,0,0x4000,64,0,0,0,0); 	       
@{$class->{'generichdr'}} = ('');
}

sub s2i {
return unpack("I1",pack("S2",@_))
}

sub _pack {
my $self = shift;
if (@_){
my @array;
push @array,@{$self->{'iphdr'}},@{$self->{"$self->{'proto'}hdr"}};
eval '$self->{\'pack\'} = '."$self->{'proto'}".'_pkt_creat (\@array)';
}
return $self->{'pack'};
}

sub packet{
my $class = shift;
return $class->_pack
}

sub set {
my ($self,$hash) = @_;
my %un = qw(id sequence unused mtu);
my %revun = reverse %un;
my $meth; 
map {$self->{'iphdr'}->$_(${$hash->{'ip'}}{$_}) } keys %{$hash->{'ip'}}
if exists $hash->{'ip'};
map {$self->{"$self->{'proto'}hdr"}->$_(${$hash->{"$self->{'proto'}"}}{$_}) }
keys %{$hash->{"$self->{'proto'}"}}
if exists $hash->{"$self->{'proto'}"};
map {   
$self->{'icmphdr'}->$_(${$hash->{'icmp'}}{$_});
if(!/gateway/){
        if($un{$_}){ 
	     $meth = $un{$_};
             $self->{icmphdr}->gateway(s2i(($self->{icmphdr}->$_()),
                              ($self->{icmphdr}->$meth())))
        }       
        elsif($revun{$_}){ 
	    $meth = $revun{$_};
            $self->{icmphdr}->gateway(s2i(($self->{icmphdr}->$meth()),
            ($self->{icmphdr}->$_())))
        }
   } 
} keys %{$hash->{icmp}} if exists $hash->{icmp};
my $saddr = $self->{iphdr}->saddr;
my $daddr = $self->{iphdr}->daddr;
$self->{iphdr}->saddr(host_to_ip($saddr)) if($saddr !~ /^-?\d*$/);
$self->{iphdr}->daddr(host_to_ip($daddr)) if($daddr !~ /^-?\d*$/);
$self->_pack(1);
}

sub bset {
my ($self,$hash,$eth) = @_;
my $array;
my $i;
my $j;
my %n = ('tcp',17,'udp',5,'icmp',9,'generic',1);
  if($eth){
$self->{'ethpack'} = substr($hash,0,14);
$hash = substr($hash,14);
@{$self->{'ethhdr'}} = @{eth_parse($self->{'ethpack'})}
  } 
  $self->{'pack'} = $hash;
  eval '$array ='."$self->{'proto'}_pkt_parse(".'$hash)'; 
  @{$self->{'iphdr'}} = @$array[0..10];
 @{$self->{"$self->{'proto'}hdr"}}= @$array[11..(@$array-1)];
  if(ref(${$self->{"$self->{'proto'}hdr"}}[$n{$self->{'proto'}}]) eq 'ARRAY'){
 $j = 0;
 $self->{'optsip'} = new Net::RawIP::opt  unless $self->{'optsip'};
 @{$self->{'optsip'}->type} = ();
 @{$self->{'optsip'}->len} = ();
 @{$self->{'optsip'}->data} = ();
    for($i=0;$i<=(@{${$self->{"$self->{'proto'}hdr"}}[$n{$self->{'proto'}}]} - 2);$i = $i + 3){
 $self->{'optsip'}->type($j,
                 ${${$self->{"$self->{'proto'}hdr"}}[$n{$self->{'proto'}}]}[$i]);
 $self->{'optsip'}->len($j,
               ${${$self->{"$self->{'proto'}hdr"}}[$n{$self->{'proto'}}]}[$i+1]);
 $self->{'optsip'}->data($j,
               ${${$self->{"$self->{'proto'}hdr"}}[$n{$self->{'proto'}}]}[$i+2]);
 $j++;
    }
  }
 if($self->{'proto'} eq 'tcp'){
  if(ref(${$self->{'tcphdr'}}[18]) eq 'ARRAY'){
$j = 0;
 $self->{'optstcp'} = new Net::RawIP::opt  unless $self->{'optstcp'};
 @{$self->{'optstcp'}->type} = ();
 @{$self->{'optstcp'}->len} = ();
 @{$self->{'optstcp'}->data} = ();
    for($i=0;$i<=(@{${$self->{'tcphdr'}}[18]} - 2);$i = $i + 3){
 $self->{'optstcp'}->type($j,
                 ${${$self->{'tcphdr'}}[18]}[$i]);
 $self->{'optstcp'}->len($j,
               ${${$self->{'tcphdr'}}[18]}[$i+1]);
 $self->{'optstcp'}->data($j,
               ${${$self->{'tcphdr'}}[18]}[$i+2]);
 $j++;
    }
  }
 }
}


sub get {
my ($self,$hash) = @_;
my @iphdr = qw(version ihl tos tot_len id frag_off ttl protocol check saddr 
daddr);
my @tcphdr = qw(source dest seq ack_seq doff res1 res2 urg ack psh rst syn
fin window check urg_ptr data);
my @udphdr = qw(source dest len check data);
my @icmphdr = qw(type code check gateway id sequence unused mtu data);
my @ethhdr = qw(dest source proto);
my %ref = ('tcp',\@tcphdr,'udp',\@udphdr,'icmp',\@icmphdr);
my @array;
map { ${$$hash{ethh}}{$_} = '$' } @{$hash->{eth}};
map { ${$$hash{iph}}{$_} = '$' } @{$hash->{ip}};

map { ${$$hash{"$self->{'proto'}h"}}{$_} = '$' } @{$hash->{"$self->{'proto'}"}}; 
map { push @array,$self->{'ethhdr'}->$_() if $hash->{'ethh'}->{$_} eq '$'
} @ethhdr if exists $hash->{'eth'};
map { push @array,$self->{'iphdr'}->$_() if $hash->{'iph'}->{$_} eq '$'
} @iphdr if exists $hash->{'ip'};
map { push @array,$self->{"$self->{'proto'}hdr"}->$_()
      if $hash->{"$self->{'proto'}h"}->{$_} eq '$' 
    } @{$ref{"$self->{'proto'}"}} if exists $hash->{"$self->{'proto'}"};
return (@array);
}

sub send {
my ($self,$delay,$times) = @_;
if(!$times){
$times = 1;
}
$self->{'raw'} = rawsock() unless $self->{'raw'};
if($self->{'proto'} eq 'icmp'){
$self->{'sock'} = set_sockaddr($self->{'iphdr'}->daddr,0);
}
else{
$self->{'sock'} = set_sockaddr($self->{'iphdr'}->daddr,
                               $self->{"$self->{'proto'}hdr"}->dest);
}
while($times){
    pkt_send ($self->{raw},$self->{'sock'},$self->{'pack'});
sleep $delay;
$times--
}
} 

sub pcapinit {
my($self,$device,$filter,$size,$tout) = @_;
my $promisc = 0x100;
my ($erbuf,$pcap,$program);
die "$erbuf" unless ($pcap = open_live($device,$size,$promisc,$tout,$erbuf));
die "compile(): check string with filter" if (compile($pcap,$program,$filter,0,0) < 0);
setfilter($pcap,$program);
return $pcap
} 

1;
__END__

=head1 NAME

Net::RawIP - Perl extension for manipulate raw ip packets with interface to B<libpcap>

=head1 SYNOPSIS

  use Net::RawIP;
  $a = new Net::RawIP;
  $a->set({ip => {saddr => 'my.target.lan',daddr => 'my.target.lan'},
           tcp => {source => 139,dest => 139,psh => 1, syn => 1}});
  $a->send;
  $a->ethnew("eth0");
  $a->ethset(source => 'my.target.lan',dest =>'my.target.lan');	   
  $a->ethsend;
  $p = $a->pcapinit("eth0","dst port 21",1500,30);
  $f = dump_open($p,"/my/home/log");
  loop $p,10,\&dump,$f;

=head1 DESCRIPTION

This package provides a class object which can be used for
creating, manipulating and sending a raw ip packets with
optional feature for manipulating ethernet headers.

B<NOTE:> Ethernet related methods now imlemented only on Linux

=head1 Exported constants

  PCAP_ERRBUF_SIZE
  PCAP_VERSION_MAJOR
  PCAP_VERSION_MINOR
  lib_pcap_h

=head1 Exported functions

open_live
open_offline
dump_open
lookupdev
lookupnet
dispatch
loop
dump
compile
setfilter
next
datalink
snapshot
is_swapped
major_version
minor_version
stats
file
fileno
perror
geterr
strerror
close
dump_close
timem

By default exported functions is a B<loop>,B<dispatch>,B<dump_open>,
B<dump>,B<open_live>,B<timem>. Use export tag B<pcap> for export all pcap 
functions.
Please read the docs for libpcap.
Exported functions B<loop> and B<dispatch> can run perl code refs
as callback for packet analyzing and printing.
If B<dump_open> open and return a valid file descriptor,this descriptor can be 
used in perlcallback as perl filehandle.Also fourth parameter for loop and 
dispatch can be array or hash reference and it can be unreferensed in perl 
callback. Function B<next> return a string scalar (next packet).Function 
B<timem()> return a string scalar which looking like B<sec>.B<microsec>, 
where B<sec> and B<microsec> is values returned by gettimeofday(3).
Please look at examples.

=head1 CONSTRUCTOR

B<C<new>>   ({
              ip       => {IPKEY => IPVALUE,...},
              ARGPROTO => {PROTOKEY => PROTOVALUE,...} 
	  })	      

B<C<ip>> is a key of hash which value is a reference of hash with 
parameters iphdr in current ip packet.

B<C<IPKEY>> is one of they (B<version> B<ihl> B<tos> B<tot_len> B<id>
B<frag_off> B<ttl> B<protocol> B<check> B<saddr> B<daddr>).
You may specify all parameters even B<check>.If you not specify parameter,
default value is used.Default values is (4,5,16,0,0,0x4000,64,6,0,0,0).
Of course checksum will be calculated if you not specify non-zero value.
Values of B<saddr> and B<daddr> may look like www.oracle.com or
205.227.44.16, even this may look like integer  if you know how
look 205.227.44.16 as unsigned int ;). 

B<C<ARGPROTO>> is one of they (B<tcp> B<udp> B<icmp> B<generic>),
this key define subclass of Net::RawIP. Default value is tcp. 


B<C<PROTOKEY>> is one of (B<source> B<dest> B<seq> B<ack_seq> B<doff> 
B<res1> B<res2> B<urg> B<ack> B<psh> B<rst> B<syn> B<fin> B<window> B<check>
B<urg_ptr> B<data>) for tcp and one of (B<type> B<code> B<check>
B<gateway> B<id> B<sequence> B<unused> B<mtu> B<data>) for icmp and
one of (B<source> B<dest> B<len> B<check> B<data>) for udp and just B<data> 
for generic.
You must specify only B<gateway> - (int) or (B<id> and B<sequence>)
- (short and short) or (B<mtu> and B<unused>) - (short and short)
for icmp because in real icmp packet it's  C union.
Default values is (0,0,0,0,5,0,0,0,0,0,0,0,0,0xffff,0,0,'') for tcp and
(0,0,0,0,0,0,0,0,'') for icmp and (0,0,0,0,'') for udp and ('') for generic.
Valid values for B<urg> B<ack> B<psh> B<rst> B<syn> B<fin> is 0 or 1.
Value of B<data> is a string. Length of result packet will be calculated
if you not specify non-zero value for B<tot_len>. 

=head1 METHODS

=over 3

=item B<proto>

return name of subclass current object e.g. B<tcp>.
No input parameters.

=item B<packet> 

return scalar which contain packed ip packet of current object.
No input parameters.

=item B<set> 

is a method for setting parameters current object. Given parameters
must look like parameters for constructor.

=item B<bset($packet,$eth)>

is a method for setting parameters current object.
B<$packet> is a scalar which contain binary structure (ip or eth packet).
This scalar must match with subclass current object.
If B<$eth> given and have non-zero value then assumed that packet is a
ethernet packet,otherwise ip packet. 

=item B<get> 

is a method for getting parameters from current object. This method return
array which filled with asked parameters in order as it ordered in
packet.
Input parameter is a hash reference. In this hash may be three keys.
They is a B<ip> and one of B<ARGPROTO>s. Value must be a array reference. This
array contain asked parameters.
E.g. you want know current value of tos from iphdr and
flags which contain tcphdr.
Here is a code :

  ($tos,$urg,$ack,$psh,$rst,$syn,$fin) = $packet->get({
            ip => [qw(tos)],
	    tcp => [qw(psh syn urg ack rst fin)]
	    });
Members in array can be given in any order.

For getting ethernet parameters use key B<eth> and values of array
(B<dest>,B<source>,B<proto>). Values of B<dest> and B<source>
look like output of ifconfig(8) e.g. 00:00:E8:43:0B:2A. 

=item B<send($delay,$times)>

is a method which used for send raw ip packet.
Input parameters is a delay seconds and a times for repeat sending.
If you not specifies parameters for B<send>,then packet will be send once
without delay. 
If you specifies for times negative value then packet will be send forever.
E.g. you want send packet 10 times with delay equal 1 second.
Here is a code :

$packet->send(1,10);

=item B<pcapinit($device,$filter,$psize,$timeout)>

is a method for some pcap init. Input parameters is a device,string with
program for filter,packet size,timeout.
This method call pcap function open_live,then compile filter string,
set filter and return B<pcap_t *>.            	         

=item B<ethnew>(B<$device>,B<dest> => B<ARGOFDEST>,B<source> => B<ARGOFSOURCE>)

is a method for init ethernet subclass for current object, B<$device> is a
required parameter,B<dest> and B<source> is optional, B<$device> is ethernet
device e.g. B<eth0>, B<ARGOFDEST> and B<ARGOFSOURCE> is a ethernet addresses
in the ethernet header for current object.

B<ARGOFDEST> and B<ARGOFSOURCE> may be given as string which contain 
just 6 bytes real ethernet adress or as it look in ifconfig(8) 
output e.g. 00:00:E8:43:0B:2A or just ip adress or hostname of target, 
then mac adress will be discovered automatically.

Ethernet frame will be send with given adresses.
By default B<source> and B<dest> will be filled with hardware address of   
B<$device>.

B<NOTE:> For using methods related for ethernet you must before initializing
ethernet subclass by B<ethnew>. 

=item B<ethset>

is a method for setting ethernet parameters for current object.
Given parameters must look like parameters for B<ethnew> without
B<$device>.

=item B<ethsend>

is a method for sending ethernet frame.
Given parameters must look like parameters for B<send>.

=item B<optset>(OPTPROTO => { type => [...],data => [...] },...)

is a method for setting IP and TCP options.
Parameters for optset must be given as key-value pairs.  
B<OPTPROTO>,s is the prototypes of options(B<ip>,B<tcp>),values is the hash
references.The keys in this hashes is B<type> and B<data>.
Value of B<type> is the array reference.
This array must be filled with integers.Refer to RFC for valid types.Value of 
B<data> also is the array reference. This array must be filled 
with strings which must contain all bytes from option except bytes 
with type and length of option.Of course indexes in this arrays must be 
equal for one option.

=item B<optget>(OPTPROTO => { type => [...] },...)  

is a method for getting IP and TCP options.
Parameters for optset must be given as key-value pairs.
B<OPTPROTO> is the prototype of options(B<ip>,B<tcp>),values is the hash
reference.The key is B<type>.Value of B<type> is the array reference.
Return value is the array which will be filled with asked type,length,data
for each type of option in order as you asked.If you not specify type then
all types,length,datas of options will be returned.
E.g. you want know all IP options from current object.
Here is a code:

@opts = $a->optget(ip => {});

E.g. you want know just IP options with type equal to 131 and 137.
Here is a code:

($t131,$l131,$d131,$t137,$l137,$d137) = $a->optget(
                                   ip =>{
				        type =>[(131,137)]
				        }        );                        

=item B<optunset>

is a method for unsetting subclass of IP or TCP options from current
object.It can be used if you  won't use options in current object.
This method must be used only after B<optset>.
Parameters for this method is the B<OPTPROTO>'s. 
E.g. you want unset IP options.
Here is a code:

$a->optunset('ip');

E.g. you want unset TCP and IP options.
Here is a code:

$a->optunset('ip','tcp');

=back

=head1 AUTHOR

Sergey Kolychev <ksv@al.lg.ua>

=head1 COPYRIGHT

Copyright (c) 1998,1999 Sergey Kolychev. All rights reserved. This program is free
software; you can redistribute it and/or modify it under the same terms
as Perl itself.

=head1 SEE ALSO

perl(1) ,tcpdump(1),RFC 791-793,RFC 768.


=cut

