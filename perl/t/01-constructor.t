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

my $r2 = Radare::r2pipe->new();

my %single = $r2->convert_to_named_parameters('/bin/ls');
is_deeply(
	\%single,
	{
		file => '/bin/ls',
		filename => '/bin/ls',
		http => '/bin/ls',
		tcp => '/bin/ls',
		url => '/bin/ls',
	},
	'single positional argument is expanded into named parameters',
);

my %named = $r2->convert_to_named_parameters(
	filename => '/bin/ls',
	url => 'http://127.0.0.1:9090',
);
is($named{file}, '/bin/ls', 'filename alias populates file');
is($named{filename}, '/bin/ls', 'filename is preserved');
is($named{http}, 'http://127.0.0.1:9090', 'url alias populates http');
is($named{url}, 'http://127.0.0.1:9090', 'url is preserved');

$r2->r2pipe_http('http://127.0.0.1:9090');
is($r2->{type}, 'http', 'http transport is selected');
is($r2->{uri}, 'http://127.0.0.1:9090/cmd/', 'http transport normalizes the command URI');
ok($r2->{ua}, 'http transport creates a user agent');

eval { $r2->convert_to_named_parameters('file', '/bin/ls', 'dangling') };
like($@, qr/unable to interpret as hash/, 'odd named arguments are rejected');

done_testing();
