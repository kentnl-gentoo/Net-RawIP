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

package Net::RawIP;
use Carp;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD);
require Exporter;
require DynaLoader;
require AutoLoader;
@ISA = qw(Exporter DynaLoader);

@EXPORT = qw(open_live dump_open dispatch dump loop);
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
minor_version stats file fileno perror geterr strerror close dump_close)  
                            ]
	       );	  	    

$VERSION = '0.01';

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
 my @proto = qw(tcp udp icmp);
 my $proto;
 unless ($class->{'proto'}){
 map {$proto = $_ if exists $args->{$_} } @proto;
 $proto = 'tcp' unless $proto;
 $class->{'proto'} = $proto;
 }
 return $class->{'proto'}
}

sub _unpack {
 my ($self,$ref) = @_;
 $self->{'iphdr'} = new Net::RawIP::iphdr;
 eval '$self->{'."$self->{'proto'}".'hdr} = new Net::RawIP::'."$self->{'proto'}".'hdr';
 eval '$self->'."$self->{proto}_default"; 
 $self->set($ref);
}

sub tcp_default {
my ($class) = @_;
@{$class->{'iphdr'}} = (4,5,16,0,0,0x4000,64,6,0,0,0);
@{$class->{'tcphdr'}} = (0,0,0,0,0,0,0,0,0,0,0,0,0,0xffff,0,0,'');
}
	       

sub tcp_pack {
my $self = shift;
if (@_){
my @array;
push @array,@{$self->{iphdr}},@{$self->{tcphdr}};
$$self{pack} = tcp_pkt_creat (\@array);
}
return $self->{pack};
}

sub set {
my ($self,$hash) = @_;
map {$self->{iphdr}->$_(${$hash->{ip}}{$_}) } keys %{$hash->{ip}};
map {$self->{tcphdr}->$_(${$hash->{tcp}}{$_}) } keys %{$hash->{tcp}};
my $saddr = $self->{iphdr}->saddr;
my $daddr = $self->{iphdr}->daddr;
$self->{iphdr}->saddr(pack("V1",$1,$2,$3,$4))
if ($saddr =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
$self->{iphdr}->daddr(pack("V1",$1,$2,$3,$4))
if ($daddr =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
$self->{iphdr}->saddr(host_to_ip($saddr)) if($saddr !~ /^-?\d*$/);
$self->{iphdr}->daddr(host_to_ip($daddr)) if($daddr !~ /^-?\d*$/);
$self->tcp_pack(1);
}

sub bset {
my ($self,$hash) = @_;
my @array;
$self->{pack} = $hash;
eval '$array ='."$self->{proto}_pkt_parse(".'$hash)'; 
@{$self->{iphdr}} = @$array[0..10];
@{$self->{"$self->{proto}hdr"}}= @$array[11..(@$array-1)]
}


sub get {
my ($self,$hash) = @_;
my @iphdr = qw(version ihl tos tot_len id frag_off ttl protocol check saddr 
daddr);
my @tcphdr = qw(source dest seq ack_seq doff res1 res2 urg ack psh rst syn
fin window check urg_ptr data);
my $ip = $self->{iphdr};
my $proto = $self->{"$self->{proto}hdr"};
my @array;
map { ${$$hash{iph}}{$_} = '$' } @{$hash->{ip}};
map { ${$$hash{"$self->{proto}h"}}{$_} = '$' } @{$hash->{"$self->{proto}"}}; 
map { push @array,$ip->$_() if $hash->{iph}->{$_} eq '$'
} @iphdr if exists $hash->{ip};
map { push @array,$proto->$_() if $hash->{"$self->{proto}h"}->{$_} eq '$' 
} @tcphdr if exists $hash->{"$self->{proto}"};
return (@array);
}

sub send {
my ($self,$delay,$times) = @_;
if(!$times){
$times = 1;
}
$self->{raw} = rawsock() unless $self->{raw};
$self->{sock} = set_sockaddr(0,0) unless $self->{sock};
while($times){
pkt_send ($self->{raw},$self->{sock},$self->{pack});
sleep $delay;
$times--
}
} 

sub pcapinit {
my($self,$device,$filter,$size,$tout) = @_;
my $promisc = 0x100;
my ($erbuf,$pcap,$program);
die "$erbuf" unless ($pcap = open_live($device,$size,$promisc,$tout,$erbuf));
compile($pcap,$program,$filter,0,0);
setfilter($pcap,$program);
return $pcap
} 
# Autoload methods go after =cut, and are processed by the autosplit program.
1;
__END__

=head1 NAME

Net::RawIP - Perl extension for manipulate raw ip packet whith interface to B<libpcap>

=head1 SYNOPSIS

  use Net::RawIP;
  $a = new Net::RawIP;
  $a->set({ip => {saddr => www.mustdie.com,daddr => www.mustdie.com},
           tcp => {source => 139,dest => 139,psh => 1, syn => 1}});
  $a->send;	   

=head1 DESCRIPTION

This package provides a class object which can be used for
creating, manipulating and sending a raw ip packets.

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
eth_tcp_pkt_parse
tcp_pkt_creat
rawsock
host_to_ip
set_sockaddr
pkt_send

By default exported functions is a B<loop>,B<dispatch>,B<dump_open>,
B<dump>,B<open_live>. Use export tag B<pcap> for export all pcap 
functions.
Please read the docs for libpcap.
Exported functions B<loop> and B<dispatch> can run perl code refs
as callback for packet analyzing and printing.
If B<dump_open> open and return a valid file descriptor,this 
descriptor can be used in perlcallback as perl filehandle.  
Function B<next> return a string scalar (next packet).
Please look at examples.

=head1 CONSTRUCTOR


C<B<new>>   ({
              ip       => {IPKEY => IPVALUE,...},
              ARGPROTO => {PROTOKEY => PROTOVALUE,...} 
	  })	      


C<B<ip>> is a key of hash which value is a reference of hash whith 
parameters iphdr in current ip packet.

C<B<IPKEY>> is one of they (B<version> B<ihl> B<tos> B<tot_len> B<id>
B<frag_off> B<ttl> B<protocol> B<check> B<saddr> B<daddr>).
You may specify all parameters even B<check>.If you not specify parameter,
default value is used.Default values is (4,5,16,0,0,0x4000,64,6,0,0,0).
Of course checksum will be calculated if you not specify non-zero value.
Values of B<saddr> and B<daddr> may look like www.oracle.com or
205.227.44.16, even this may look like integer  if you know how
look 205.227.44.16 as unsigned int ;). 

C<B<ARGPROTO>> is one of they (B<tcp> B<udp> B<icmp>),this key define 
subclass of Net::RawIP. Default value is tcp. 

C<B<NOTE:>> Currently only tcp is implemented !   

C<B<PROTOKEY>> is one of they (B<source> B<dest> B<seq> B<ack_seq> B<doff> 
B<res1> B<res2> B<urg> B<ack> B<psh> B<rst> B<syn> B<fin> B<window> B<check>
B<urg_ptr> B<data>)
Default values is (0,0,0,0,0,0,0,0,0,0,0,0,0,0xffff,0,0,''). 
Valid values for B<urg> B<ack> B<psh> B<rst> B<syn> B<fin> is 0 or 1.
Value of data is a string. Length of result packet will be calculated
if you not specify non-zero value for B<tot_len>. 

=head1 METHODS

=item B<proto> 
return name of subclass current object e.g. B<tcp>.

=item B<set> 
is a method for setting parameters current object. Given parameters
must look like parameters for constructor.

=item B<bset>
is a method for setting parameters current object.
Single parameter is a scalar which contain binary structure (ip packet).
This scalar must match whith subclass current object.

=item B<get> 
is a method for getting parameters from current object. This method return
array which filled whith asked parameters in order as it ordered in
ip packet.
Input parameter is a hash reference. In this hash may be two keys.
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

=item B<send($delay,$times)>
is a method which used for send raw ip packet.
Input parameters is a delay seconds and a times for repeat sending.
If you not specifies parameters for B<send>,then packet will be send once
whithout delay. 
If you specifies for times negative value packet will be send forever.
E.g. you want send packet 10 times whith delay equal 1 second.
Here is a code :

$packet->send(1,10);

=item B<pcapinit($device,$filter,$psize,$timeout)>
is a method for some pcap init. Input parameters is a device,string whith
program for filter,packet size,timeout.
This method call pcap functons open_live,then compile filter string,
set filter and return B<pcap_t *>.            	         

=head1 AUTHOR

Sergey Kolychev <ksv@al.lg.ua>

=head1 COPYRIGHT

Copyright (c) 1998 Sergey Kolychev. All rights reserved. This program is free
software; you can redistribute it and/or modify it under the same terms
as Perl itself.

=head1 SEE ALSO

perl(1) ,tcpdump(1),RFC 791,RFC 793.

=cut