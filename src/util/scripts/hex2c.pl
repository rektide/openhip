#!/usr/bin/perl -W
# Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
# Take a hex dump (from RFC) and put it into C-style octets

my $wrap = 12;
my $count = 0;
#my $LEAD = 12; # RFC 2412
my $LEAD = 6; # RFC 3526
#my $LEAD = 3; # RFC 3526

while (<>)
{
	# this is only a sanity check, 12 spaces + 8 aplha-numeric
	if (/\s{$LEAD}\w{8}/) {
		@line = split();
		for($i=0; $i<scalar(@line); $i++) {
			print "0x" . substr($line[$i],0,2) . ",";
			print "0x" . substr($line[$i],2,2) . ",";
			print "0x" . substr($line[$i],4,2) . ",";
			print "0x" . substr($line[$i],6,2) . ",";
			$count += 4;
			if ($count >= $wrap) {
				print "\n";
				$count = 0;
			}
		}
		
	}

}
