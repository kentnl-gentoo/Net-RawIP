package Net::RawIP::generichdr;
use strict;
use warnings;
use Class::Struct qw(struct);
our @generichdr = qw(data);
struct ( 'Net::RawIP::generichdr' => [map { $_ => '$' } @generichdr ] );

1;
