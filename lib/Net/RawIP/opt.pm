package Net::RawIP::opt;
use strict;
use warnings;
use Class::Struct qw(struct);
my @opt = qw(type len data);
struct ( 'Net::RawIP::opt' => [map { $_ => '@' } @opt ] );

1;
