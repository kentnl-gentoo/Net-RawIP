package Net::RawIP::icmphdr;
use strict;
use warnings;
use Class::Struct qw(struct);
our @icmphdr = qw(type code check gateway id sequence unused mtu data);
struct ( 'Net::RawIP::icmphdr' => [map { $_ => '$' } @icmphdr ] );

1;
