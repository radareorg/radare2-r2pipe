# Declare namespace
package Pwn::r2pipe;

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
our $VERSION = 0.2;

sub new {
    my $class = shift;
    my $self = {};

    # Bless you.
    bless $self, $class;

    # Open connection to r2 if argument was given.
    $self->parse_filename(shift) if @_;

    return $self;
}

sub parse_filename {
    my ($self, $filename) = @_;
    if($filename =~ m#^http://#i) { # It's an HTTP server
        $self->r2pipe_http($filename);
    } elsif($filename =~ m#^tcp://#i) { # TCP server
        $self->r2pipe_tcp($filename);
    } else { # File (probably...)
        $self->r2pipe_file($filename);
    }
    # So that open() knows if it's already opened a file
    $self->{opened} = 1; 
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
        die "r2pipe_file(): File '$filename' is not readable.\n";
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

    # Spawn
    $self->{r2}->spawn("r2 -q0 $file 2>/dev/null");
    $self->{r2}->read();
}

# Input: Filename to open in r2
sub open {
    my $self = shift;
    return -1 if scalar(@_) != 1; # No argument to open :(
    return -2 if $self->{opened}; # We already have opened a file in r2?

    # Open...
    $self->parse_filename(shift);
}

sub cmd {
    my $self = shift;

    # Argument handling
    return -1 if scalar(@_) != 1; # No command to execute? :(
    return -2 if ! $self->{opened}; # No file was loaded. :(
    my $command = shift;

    # Route the command...
    my $method_name = 'cmd_' . $self->{type}; # Cause I'm lazy

    # Execute command
    my $output = $self->$method_name($command);
    $output =~ s/(\r?\n)*$//;
    return $output;
}

sub cmdj {
    my $self = shift;
    return decode_json($self->cmd(@_));
}

sub cmd_http {
    my ($self, $command) = @_;
    my $url = $self->{uri} . uri_escape($command);
    my $req = HTTP::Request->new(GET => $url);
    my $response = $self->{ua}->request($req)->content;
    return $response;
}

sub cmd_tcp {
    my ($self, $command) = @_;
    $self->{socket}->write($command . "\r\n", length($command) + 2);
    my ($output, $data) = ('', '');
    $self->{socket}->recv($data, 9000);
    while($data) {
        $output .= $data;
        $self->{socket}->recv($data, 512);
    }
    return $output;
}

sub cmd_file {
    my ($self, $command) = @_;
    $self->{r2}->write($command . "\n");

    # Read the output...
    my $output = $self->{r2}->read();
    while($output !~ /\x00$/) { # Gambatte ne!
        $output .= $self->{r2}->read();
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
    $self->{opened} = undef;
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

Pwn::r2pipe - Interface with radare2

=head1 VERSION

version 0.1

=head1 SYNOPSIS

    use Pwn::r2pipe;

    my $r2 = Pwn::r2pipe->new('/bin/ls');
    $r2->cmd('iI');
    $r2->cmdj('ij');
    $r2->quit();

    # Other stuff
    $r2 = Pwn::r2pipe->new;
    $r2->open('/bin/ls');
    $r2->cmd('pi 5');
    $r2->close(); # Same as quit()

=head1 DESCRIPTION

The r2pipe APIs are based on a single r2 primitive found behind r_core_cmd_str() which is a function that accepts a string parameter describing the r2 command to run and returns a string with the result.

The decision behind this design comes from a series of benchmarks with different libffi implementations and resulted that using the native API is more complex and slower than just using raw command strings and parsing the output.

As long as the output can be tricky to parse, it's recommended to use the JSON output and deserializing them into native language objects which results much more handy than handling and maintaining internal data structures and pointers.

Also, memory management results into a much simpler thing because you only have to care about freeing the resulting string.

=head1 METHODS

=head2 new($file)

The C<new> constructor initializes r2 and optionally loads a file into r2.

=head2 open($file)

Opens the file in radare2. It also supports radare2 over TCP sockets (`$r2pipe->open("tcp://127.0.0.1:9080")`) and HTTP (`$r2pipe->open("http://127.0.0.1:9090")`).

=head2 cmd($command)

Executes the command in radare2.

=head2 cmdj($command)

Executes the command in radare2 and JSON decodes the result into a Perl datastructure.

=head2 close

Closes the connection to radare2.

=head2 quit

Closes the connection to radare2. This is exactly the same as the close method.

=cut
