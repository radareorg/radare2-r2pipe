use strict;
use warnings;

use Test::More;

my $loaded = eval {
	require Radare::r2pipe;
	Radare::r2pipe->import();
	1;
};

ok($loaded, 'Radare::r2pipe loads') or diag($@);
done_testing() if !$loaded;
exit 0 if !$loaded;

my $r2_bin = Radare::r2pipe::r2_exists();
my ($sample_file) = grep { -f $_ && -r _ } qw(/bin/ls /usr/bin/true /bin/sh);
my $startup_error = '';
my $r2;

if ($r2_bin && $sample_file) {
	$r2 = eval { Radare::r2pipe->new($sample_file) };
	$startup_error = $@ if !$r2;
}

SKIP: {
	skip 'radare2 executable not found in PATH', 4 if !$r2_bin;
	skip 'no readable sample binary found for smoke test', 4 if !$sample_file;
	skip "unable to start $r2_bin for smoke test: $startup_error", 4 if !$r2;

	my $json = $r2->cmd('ij');
	ok(defined $json && $json ne '', 'ij returns JSON output');

	my $info = eval { $r2->cmdj('ij') };
	is($@, '', 'cmdj decodes the JSON output');
	isa_ok($info, 'HASH');
	ok(exists $info->{bin} || exists $info->{core}, 'decoded output contains expected metadata');

	$r2->close();
}

done_testing();
