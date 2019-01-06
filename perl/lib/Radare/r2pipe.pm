# Declare namespace
package Radare::r2pipe;

# Declare dependencies
use strict;
use warnings;

# Local r2 connection
use IO::Pty::Easy;

# r2 using TCP sockets
use IO::Socket::INET;

# r2 using HTTP web server
use LWP::UserAgent;
use URI::Escape;

# JSON support
use JSON;

# Version
our $VERSION = 0.3;

sub new {
	my $class = shift;
	my $self = {};

	# Bless you.
	bless $self, $class;

	# Open connection to r2 if argument was given.
	$self->parse_arguments(@_) if @_;

	return $self;
}

sub parse_arguments {
	my ($self, @arguments) = @_;
	my %parsed_arguments = $self->convert_to_named_parameters(@arguments);
	$self->{arguments} = \%parsed_arguments;
	if(defined $parsed_arguments{http} && $parsed_arguments{http} =~ m#^http://#i) { # It's an HTTP server
		$self->r2pipe_http($parsed_arguments{http});
	} elsif(defined $parsed_arguments{tcp} && $parsed_arguments{tcp} =~ m#^tcp://#i) { # TCP server
		$self->r2pipe_tcp($parsed_arguments{tcp});
	} else { # File (probably...)
		$self->r2pipe_file($parsed_arguments{file});
	}
}

sub convert_to_named_parameters {
	my ($self, @arguments) = @_;
	my %parsed_arguments = ();
	if(@arguments == 1) {
		# Whatever the argument was (tcp, http or filepath), handle it.
		$parsed_arguments{filename} = $arguments[0];
		$parsed_arguments{file} = $arguments[0];
		$parsed_arguments{tcp} = $arguments[0];
		$parsed_arguments{url} = $arguments[0];
		$parsed_arguments{http} = $arguments[0];
	} else {
		die "parse_arguments(): More than one argument but unable to interpret as hash\n" if @arguments % 2;
		%parsed_arguments = @arguments;
		$parsed_arguments{http} = $parsed_arguments{url} if defined $parsed_arguments{url};
		$parsed_arguments{url} = $parsed_arguments{http} if defined $parsed_arguments{http};
		$parsed_arguments{file} = $parsed_arguments{filename} if defined $parsed_arguments{filename};
		$parsed_arguments{filename} = $parsed_arguments{file} if defined $parsed_arguments{file};
	}
	return %parsed_arguments;
}

sub r2pipe_http {
	my ($self, $base_uri) = @_;
	$base_uri .= '/' if $base_uri !~ m#/$#;
	$base_uri .= 'cmd/';

	# Store type and URI in instance variables
	$self->{type} = 'http';
	$self->{uri} = $base_uri;
	$self->{ua} = LWP::UserAgent->new;
}

sub r2pipe_tcp {
	my ($self, $filename) = @_;
	my ($hostname, $port) = $filename =~ m#^tcp://([^:]+):(\d+)/?#i;

	$self->{socket}->close() if $self->{socket}; # We can be called by cmd_tcp if the socket is closed already...

	# Open TCP socket to r2
	my $socket = new IO::Socket::INET(PeerHost => $hostname, PeerPort => $port, Proto => 'tcp');
	die "r2pipe_tcp(): Could not connect to '$hostname:$port': $!\n" unless $socket;
	$socket->autoflush(1);

	# Store type and socket
	$self->{type} = 'tcp';
	$self->{socket} = $socket;
}

sub r2pipe_file {
	my ($self, $filename) = @_;
	if(!(-e $filename && -f $filename && -r $filename)) { # Cannot read file :(
		die "r2pipe_file(): File '$filename' is not readable.\n" unless $filename eq '-';
	}
	# Store type and URI in instance
	$self->{type} = 'file';
	$self->{file} = $filename;
	# Spawn process
	$self->spawn_r2($filename);
}

sub r2_exists {
	`which r2`;
}

sub spawn_r2 {
	my ($self, $file) = @_;
	die "spawn_r2(): No radare2 found in PATH\n" if ! r2_exists();

	# Create PTY and store
	my $r2pipe = IO::Pty::Easy->new;
	$self->{r2} = $r2pipe;

	# Setup command...
	my $cmd = 'radare2 -q0 ';
	$cmd .= '-d ' if $self->{arguments}->{debug};
	$cmd .= '-w ' if $self->{arguments}->{writable} || $self->{arguments}->{writeable};
	$cmd .= $file;
	$cmd .= ' 2>/dev/null';

	# Spawn
	$self->{r2}->spawn($cmd);
	$self->{r2}->read();

	# -A doesn't work with -q0 at this point, so just manually do it ;)
	if($self->{arguments}->{analyse} || $self->{arguments}->{analyze}) {
		print $self->cmd("aaa");
	}
}

sub cmd {
	my $self = shift;

	# Argument handling
	return -1 if scalar(@_) < 1; # No command to execute? :(
	my $command = shift;
	my $dontloop = 0;
	$dontloop = shift if @_ == 2;

	# Route the command...
	my $method_name = 'cmd_' . $self->{type}; # Cause I'm lazy

	# Execute command
	my $output = $self->$method_name($command, $dontloop);
	$output =~ s/(\r?\n)*$//;
	$output =~ s/\x00*$//;
	return $output;
}

sub cmdj {
	my $self = shift;
	my $cmd_result = $self->cmd(@_);
	$cmd_result = "{}" if ! $cmd_result;
	return decode_json($cmd_result);
}

sub cmd_http {
	my ($self, $command, $dontloop) = @_;
	my $url = $self->{uri} . uri_escape($command);
	my $req = HTTP::Request->new(GET => $url);
	my $response = $self->{ua}->request($req)->content;
	return $response;
}

sub cmd_tcp {
	my ($self, $command, $dontloop) = @_;

	# With some testing it turns out the connection is dropped by r2 after 1 cmd() output...
	# So, we reinitialize our connection before doing anything ...
	$self->r2pipe_tcp($self->{arguments}->{tcp});

	# Write the command to it...
	$self->{socket}->write($command . "\r\n", length($command) + 2);
	my ($output, $data) = ('', '');
	$self->{socket}->recv($data, 128);
	while($data) {
		$output .= $data;
		$self->{socket}->recv($data, 128);
	}
	return $output;
}

sub cmd_file {
	my ($self, $command, $dontloop) = @_;
	my $pty_result = $self->{r2}->write($command . "\n", 1);

	# Read the output...
	my $output = $self->{r2}->read(1);
	if($dontloop == 0) { # We loop
		while(!$output || $output !~ /\x00$/) {
			$output .= $self->{r2}->read();
		}
	}
	# Clean up...
	$output =~ s/^\x00//;

	# Return
	return $output;
}

sub quit {
	my $self = shift;

	# Routing...
	my $quit_method = 'quit_' . $self->{type};

	# Calling
	$self->$quit_method();
	$self->{type} = undef;
}

sub quit_file {
	my $self = shift;
	$self->{r2}->close();
	$self->{file} = undef;
}

sub quit_tcp {
	my $self = shift;
	$self->{socket}->close();
}

sub quit_http {
	my $self = shift;
	$self->{ua} = undef;
	$self->{uri} = undef;
}

# Just for handiness sake.
sub close {
	my $self = shift;
	$self->quit();
}

1;

__END__
=pod

=head1 NAME

Radare::r2pipe - Interface with radare2

=head1 VERSION

version 0.3

=head1 SYNOPSIS

    use Radare::r2pipe;
    use Data::Printer;

    my $r2 = Radare::r2pipe->new('/bin/ls');
    print "Information about the /bin/ls binary:\n";
    print $r2->cmd('iI');
    print "Information about the /bin/ls binary in JSON: ";
    print $r2->cmd('ij') . "\n";
    print "Information about the /bin/ls binary in a native Perl datastructure:\n";
    p $r2->cmdj('ij');
    $r2->quit();

    # Other stuff
    print "Opening /bin/ls with -A (analyze) flag.\n";
    $r2 = Radare::r2pipe->new(file => '/bin/ls', analyse => 1); # Opens r2 with -A option.
    print "Functions found in /bin/ls:\n";
    print $r2->cmd('afl') . "\n";
    $r2->close(); # Same as quit()

See `t/test.pl` for more examples on usage such as debugging, writing and etc.

=head1 DESCRIPTION

The r2pipe APIs are based on a single r2 primitive found behind r_core_cmd_str() which is a function that accepts a string parameter describing the r2 command to run and returns a string with the result.

The decision behind this design comes from a series of benchmarks with different libffi implementations and resulted that using the native API is more complex and slower than just using raw command strings and parsing the output.

As long as the output can be tricky to parse, it's recommended to use the JSON output and deserializing them into native language objects which results much more handy than handling and maintaining internal data structures and pointers.

Also, memory management results into a much simpler thing because you only have to care about freeing the resulting string.

=head1 METHODS

=head2 new($file)

The C<new> constructor initializes r2 and optionally loads a file into r2. There's support for TCP and HTTP as well.
TCP: `Radare::r2pipe->new("tcp://127.0.0.1:9080")`) and HTTP (`Radare::r2pipe->new("http://127.0.0.1:9090")`.

Named parameters are also possible:
`Radare::r2pipe->new(file => "/bin/ls", analyse => 1, debug => 1);`

=head2 cmd($command)

Executes the command in radare2.

=head2 cmdj($command)

Executes the command in radare2 and JSON decodes the result into a Perl datastructure.

=head2 close

Closes the connection to radare2.

=head2 quit

Closes the connection to radare2. This is exactly the same as the close method.

=cut
