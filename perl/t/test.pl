use Pwn::r2pipe;

print "General functionality test...\n";
my $r2pipe = Pwn::r2pipe->new("/bin/ls");
print $r2pipe->cmd("pi 10");
print $r2pipe->cmd("iI");
my $ds = $r2pipe->cmdj("ij");
print "Architecture: " . $ds->{bin}->{machine} . "\n";
$r2pipe->quit();

print "\n\nTesting open()...\n";
my $o = Pwn::r2pipe->new;
$o->open("/bin/ls");
print $o->cmd('iI');
$o->quit();

print "\n\nTesting TCP...\n";
my $tcp = Pwn::r2pipe->new("tcp://127.0.0.1:9080");
print $tcp->cmd('pi 20') . "\n";
$tcp->quit();

print "\n\nTesting HTTP...\n";
my $http = Pwn::r2pipe->new("http://127.0.0.1:9090");
my $output = $http->cmd('pi 30');
print "Output: $output\n";
$http->close();
