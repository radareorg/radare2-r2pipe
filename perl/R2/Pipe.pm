#!/usr/bin/perl -w

use strict;
use IPC::Open2;
use IO::Handle;

package R2::Pipe;

local $|=1;

my $Reader;
my $Writer;
my $pid;
my $fh;

sub new {
	my $class = shift;
	my $file = shift;
	my $self = {};
	bless $self, $class;
	use Env qw ($R2PIPE_IN $R2PIPE_OUT);
	if ($R2PIPE_IN && $R2PIPE_OUT) {
		$R2PIPE_IN = 0+$R2PIPE_IN;
		$R2PIPE_OUT = 0+$R2PIPE_OUT;
		open $Reader, "<&=", $R2PIPE_IN or die "cannot open reader pipe";
		open $Writer, ">&=", $R2PIPE_OUT or die "cannot open writer pipe";
		autoflush $Reader 1;
		autoflush $Writer 1;
		undef $pid;
	} else {
		$pid = IPC::Open2::open2 ($Reader, $Writer, "r2 -q0 $file") or die;
		local $/="\0";
		<$Reader>;
	}
	return $self;
}

sub cmd {
	shift;
	my $cmd = shift;
	print $Writer ("$cmd\n") or die("error");
	local $/="\0";
	my $res = <$Reader>;
	return $res;
}

sub quit {
	cmd ("q!");
	undef $Reader;
	undef $Writer;
	waitpid($pid, 0);
	close $pid if $pid;
}

1;
