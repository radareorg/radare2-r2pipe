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
