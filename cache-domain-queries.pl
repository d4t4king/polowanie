#!/usr/bin/perl -w


use strict;
use warnings;
use Term::ANSIColor;
use Data::Dumper;

my (%tlds, %ttdomains, %domains, %mime_types);
if ((defined($ARGV[0])) && ($ARGV[0] ne "")) {
	if (( -e $ARGV[0] ) && (! -z $ARGV[0])) {
		open IN, $ARGV[0] or die "Couldn't open input file ($ARGV[0]): $! \n";
		while (my $line = <IN>) {
			chomp($line);
			#0397706.395     40 192.168.1.10 TCP_MISS/202 478 POST http://telemetry.battle.net/api/submit - ORIGINAL_DST/24.105.29.23 application/json
			my ($udate, $j1, $client, $cache_status, $j2, $http_action, $url, $j3, $j4, $mime_type) = split(" ", $line);
			$mime_types{$mime_type}++;
			if ($url =~ /https?:\/\/(.*?)\//) {
				my $d = $1; $domains{$d}++;
				my @parts = split(/\./, $d);
				my $tld = $parts[-1];
				#print STDERR colored("URL=$url \n", "magenta");
				#print "SCALAR: ".scalar(@parts)."  \$\#: ".$#parts." \n";
				#print "-2: ".$parts[-2]."  -1: ".$parts[-1]." \n";
				if ($tld =~ /[^a-zA-Z]+/) {
					if (($tld =~ /\d+/) && (($tld >= 0) && ($tld <= 255))) {
						#print STDERR "Likely an unresolved IP. \n";		# deal with this later
					} else {
						warn colored("Unexpected characters in TLD.", "bold yellow");
						print STDERR colored("URL=$url \n", "yellow");
						print STDERR colored("TLD=$tld \n", "yellow");
					}
				} else {
					unless (length($tld) > 5) { 
						$tlds{$tld}++;
						$ttdomains{"$parts[-2].$parts[-1]"}++;
					}
				}
			} elsif ($url =~ /^cache_object/) {
				# do nothing for now
			} elsif ($url =~ /^error:invalid-request/) {
				# still do nothing, but this will be interesting later, maybe
			} else { warn colored("URL didn't match domain regex: $url \n", "bold yellow"); }
		}
	} else {
		die colored("There was a problem with the input file ($ARGV[0]): $! \n", "bold red");
	}
} else {
	die colored("You need to specify a cache log to parse as an argument! \n", "bold red");
}

my $i = 0;
print colored("Found the following unique top-level domains: \n", "bold cyan");
foreach my $t ( sort { $tlds{$b} <=> $tlds{$a} } keys %tlds ) {
	printf "%10s %-9d \n", $t, $tlds{$t};
}
print colored("Found the following unique primary domains: \n", "bold cyan");
foreach my $t ( sort { $ttdomains{$b} <=> $ttdomains{$a} } keys %ttdomains ) {
	printf "%32s %-9d \n", $t, $ttdomains{$t};
}
#print colored("Found the following unique domains: \n", "bold cyan");
#foreach my $dom ( sort { $domains{$b} <=> $domains{$a} } keys %domains ) {
#	print "\t$dom\t\t$domains{$dom}\n";
#}
	
