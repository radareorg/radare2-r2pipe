use strict;
use warnings;

use Test::More;

my $loaded = eval {
	require Radare::r2pipe;
	Radare::r2pipe->import();
	1;
};

ok($loaded, 'Radare::r2pipe loads') or diag($@);

if ($loaded) {
	my $r2 = Radare::r2pipe->new();
	isa_ok($r2, 'Radare::r2pipe');
	is($r2->cmd(), -1, 'cmd without arguments returns -1');
}

done_testing();
