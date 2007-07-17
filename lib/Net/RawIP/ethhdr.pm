package Net::RawIP::ethhdr;
use strict;
use warnings;
use Class::Struct qw(struct);
our @ethhdr = qw(dest source proto);
struct ( 'Net::RawIP::ethhdr' => [map { $_ => '$' } @ethhdr ] );

1;
