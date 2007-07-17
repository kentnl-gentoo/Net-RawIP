package Net::RawIP::udphdr;
use strict;
use warnings;
use Class::Struct qw(struct);
our @udphdr = qw(source dest len check data);
struct ( 'Net::RawIP::udphdr' => [map { $_ => '$' } @udphdr ] );

1;
