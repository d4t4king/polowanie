#!/usr/bin/perl -w 

use strict;
use warnings;
use Term::ANSIColor;
use Data::Dumper;
use Net::Whois::Parser;

open IN, "<$ARGV[0]" or die colored("Couldn't open input file ($ARGV[0]) for reading: $! \n", "bold red");
while (my $domain = <IN>) {
	chomp($domain);
	#Net::Whois is very limited.
	#my $w = new Net::Whois::Domain $domain or die colored("Can't connect to Whois server. \n", "bold red");
	#unless ($w->ok) { warn colored("No match for $domain \n", "bold magenta"); }
	#print Dumper($w);
	my $wout = `whois $domain 2>&1`;
	print "$wout \n";
	print "[**] Press ENTER to continue..... \n";
	<STDIN>;
}
close IN or die colored("Couldn't close input file: $! \n", "bold red");

