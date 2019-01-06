use strict;
use warnings;

use Radare::r2pipe;
use Data::Printer;

my $filename = "/bin/ls";

# Test just 1 parameter == file
my $r1 = Radare::r2pipe->new($filename);
print $r1->cmd('afl'); # Doesn't return anything because we haven't run analyse
$r1->close();

print "press enter";
<STDIN>;

# Test named parameter file
my $r2 = Radare::r2pipe->new(file => $filename);
$r2->close();
$r2 = Radare::r2pipe->new(filename => $filename);
$r2->quit();

print "press enter";
<STDIN>;

# Test analyse
my $r3 = Radare::r2pipe->new(file => $filename, analyse => 1);
print "Executing 'afl', since 'analyse' option was given, this should print a list of found functions:\n";
print $r3->cmd('afl');
$r3->close();

print "press enter";
<STDIN>;

# Test debugging
my $r4 = Radare::r2pipe->new(file => $filename, debug => 1, analyse => 1);
print "Showing location of main():\n";
print $r4->cmd('? main~hex[1]');
print "Setting breakpoint on main...\n";
$r4->cmd('db main');
print "Start execution from entry0...\n";
print $r4->cmd('dc');
print "We are now blocked at main...\n";
print "Showing the memory map:\n";
print $r4->cmd('dm');
print "\n";
print "Showing the RIP register value (should be equal to main() function):\n";
print $r4->cmd('dr~rip');
print "Continue with execution, should print list of files since we are executing /bin/ls:\n";
print $r4->cmd('dc');
$r4->close();

print "press enter";
<STDIN>;

# Test writing
my $r5 = Radare::r2pipe->new('file' => '-', writeable => 1);
$r5->cmd('wx 909090');
p $r5->cmd('px');
$r5->close();

print "press enter";
<STDIN>;

# Test removing null bytes at the end of output, this gave problems with json_decode
# "garbage after JSON object, at character offset 686 ..."
my $r6 = Radare::r2pipe->new($filename);
my $ds = $r6->cmdj("ij");
p $ds;

print "press enter";
<STDIN>;

my $r7 = Radare::r2pipe->new($filename);
print "General test: printing ten instructions:\n";
print $r7->cmd("pi 10");
print "General test: printing it as JSON:\n";
print "Raw JSON: ";
print $r7->cmd("pij 10"); print "\n";
p $r7->cmdj("pij 10"); print "\n";

print "press enter after opening r2 with HTTP interface: r2 -qc=H /bin/ls &\n";
<STDIN>;
my $http = Radare::r2pipe->new("http://127.0.0.1:9090");
print "General test: printing ten instructions:\n";
print $http->cmd('pi 10');
print "General test: printing it as JSON:\n";
print "Raw JSON: ";
print $http->cmd("pij 10"); print "\n";
p $http->cmdj("pij 10"); print "\n";
$http->close();

print "press enter after opening r2 with TCP interface: r2 -qc.:9080 /bin/ls &\n";
<STDIN>;

my $tcp = Radare::r2pipe->new("tcp://127.0.0.1:9080");
print "General test: printing ten instructions:\n";
print $tcp->cmd('pi 10') . "\n";
print "General test: printing it as JSON:\n";
print "Raw JSON: ";
print $tcp->cmd("pij 10"); print "\n";
p $tcp->cmdj("pij 10"); print "\n";
$tcp->quit();
