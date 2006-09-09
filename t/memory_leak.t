#!/usr/bin/perl
use strict;
use warnings;

use Test::More;
my $tests;

use Data::Dumper qw(Dumper);
eval {
    require Proc::ProcessTable;
};
if ($@) {
    plan skip_all  => "Proc::ProcessTable is needed for this test";
}
else {
    plan tests => $tests;
}

sub get_process_size {
    my ($pid) = @_;
    my $pt = Proc::ProcessTable->new;
    foreach my $p ( @{$pt->table} ) {
        return $p->size if $pid == $p->pid;
    }
    return;
}

my $start_size = get_process_size($$);
diag "Testing memory leak";
diag "Start size: $start_size";
my $warn;
BEGIN {
    $SIG{__WARN__} = sub { $warn = shift };
}

use_ok 'Net::RawIP';
like($warn, qr{Must have EUID == 0 to use Net::RawIP}, 'warning at load time');
BEGIN { $tests += 2; }

$warn = '';
diag "Testing Net::RawIP v$Net::RawIP::VERSION";

my $count;
BEGIN { $count = 10000; }
for (1..$count) {
    my $n = Net::RawIP->new({ udp => {} });
    $n->set({
                ip => {
                            saddr => 1,
                            daddr => 2,
                    },
                udp => {
                            source => 0,
                            dest   => 100,
                            data   => 'payload',
                        },
                });
}
my $size_change = get_process_size($$) - $start_size;
diag "Size change was: $size_change";
cmp_ok($size_change, '<', 40_000, 'normally it should be 0 but we are satisfied with 40,000 here');
BEGIN { $tests += 1; }




