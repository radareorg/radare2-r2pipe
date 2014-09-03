#!/usr/bin/perl -w

use strict;
use IPC::Open2;

package R2::Pipe;

my $file;
my $fh;

local $|=1;

sub new {
	my $class = shift;
	$file = shift;
	my $self = {};
	bless $self, $class;
	$self->_initialize ();
	return $self;
}

my $Reader;
my $Writer;
my $pid;

sub _initialize {
	$pid = IPC::Open2::open2 ($Reader, $Writer, "r2 -q0 $file") or die;
	local $/="\0";
	<$Reader>; #// read until null byte
}

sub cmd {
	shift;
	print $Writer (shift."\n");
	local $/="\0";
	return <$Reader>;
}
sub quit {
	cmd ("q!");

	close $Reader;
	close $Writer;
	waitpid($pid, 0);
	close $pid;
}

1;
