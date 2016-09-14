use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile (
	NAME		=>	'Pwn::r2pipe',
	AUTHOR		=> 	'adri',
	VERSION_FROM	=>	'lib/Pwn/r2pipe.pm',
	ABSTRACT_FROM	=>	'lib/Pwn/r2pipe.pm',
	PREREQ_PM	=>	{'JSON' => 0, 'IO::Pty::Easy' => 0, 'IO::Socket::INET' => 0, 'LWP::UserAgent' => 0, 'URI::Escape' => 0},
);
