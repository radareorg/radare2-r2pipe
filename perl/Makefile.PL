use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile (
	NAME		=>	'Radare::r2pipe',
	AUTHOR		=> 	'adri',
	VERSION_FROM	=>	'lib/Radare/r2pipe.pm',
	ABSTRACT_FROM	=>	'lib/Radare/r2pipe.pm',
	FIRST_MAKEFILE	=>	'Makefile.perl',
	PREREQ_PM	=>	{'Encode' => 0, 'HTTP::Tiny' => 0, 'IO::Handle' => 0, 'IO::Socket::INET' => 0, 'IPC::Open2' => 0, 'JSON::PP' => 0},
);
