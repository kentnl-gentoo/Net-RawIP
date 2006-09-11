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
my $warn = '';
BEGIN {
    $SIG{__WARN__} = sub { $warn = shift };
}

use_ok 'Net::RawIP';
like($warn, qr{Must have EUID == 0 to use Net::RawIP}, 'warning at load time');
BEGIN { $tests += 2; }

$warn = '';
diag "Testing Net::RawIP v$Net::RawIP::VERSION";

# one can run this test giving a number on the command line
# 10,000 seems to be reasonable
my $count = shift || 10_000;
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
cmp_ok($size_change, '<', 1_100_000, 
    'normally it should be 0 but we are satisfied with 1,100,000 here');
BEGIN { $tests += 1; }
# Once upon a time there was a memory leak on Solaris created by the above
# loop.
#
# In order to test the fix I created this test.
# On my development Ubuntu GNU/Linux machine the 
# starting size was around 7,300,000 bytes
# while the size change was constantly 1,064,960 
# no matter if I ran the loop 1000 times or 1,000,000 times 
# (though the latter took 5 minutes...)
# I guess this the memory footprint of the external libraries that are loaded
# during run time and there is no memory leek.




