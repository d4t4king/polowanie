#!/usr/bin/perl -w


use strict;
use warnings;
no if $] >= 5.017011, warnings => 'experimental::smartmatch';
use feature qw( switch );
use Term::ANSIColor;
use Data::Dumper;
use Getopt::Long;

my ($help, $verbose, $depth, $threshold, $show_tlds, $whitelist, $top, $bottom, $dump);
$depth = 10;
$threshold = 0;
$verbose = 0;
$help = 0;
$show_tlds = 0;
$top = 0;
$bottom = 1;		# defaults to bottom=true
$dump = 0;
GetOptions(
	"h|?|help"			=>	\$help,
	"v|verbose+"		=>	\$verbose,
	"d|depth=s"			=>	\$depth,
	"t|threshold=s"		=>	\$threshold,
	"show-tlds"			=>	\$show_tlds,
	"w|whitelist=s"		=>	\$whitelist,
	"top"				=>	\$top,
	"bottom"			=>	\$bottom,
	"dump=s"			=>	\$dump,
);

my (%tlds, %ttdomains, %domains, %whitelist, %xfers);
my (@sorted);

if ($help) { &show_help(); }

if ($whitelist) { %whitelist = &load_whitelist($whitelist); }

if ((defined($ARGV[0])) && ($ARGV[0] ne "")) {
	if (( -e $ARGV[0] ) && (! -z $ARGV[0])) {
		open IN, $ARGV[0] or die "[EE] Couldn't open input file ($ARGV[0]): $! \n";
		while (my $line = <IN>) {
			chomp($line);
			my ($mon, $day, $time, $process, $action, $domain, $client, $j1, $remote_ip, $remote_dns);
			given ($line) {
				when ($line =~ / query\[AXFR\] /) {
					#Jan 16 00:38:55 dnsmasq[2349]: query[A] ssw.live.com from 192.168.1.135
					($mon, $day, $time, $process, $action, $domain, $j1, $client) = split(" ", $line);
					$xfers{$client}++;
				}
				when ($line =~ / query\[A+\] /) {
					#Jan 16 00:38:55 dnsmasq[2349]: query[A] ssw.live.com from 192.168.1.135
					($mon, $day, $time, $process, $action, $domain, $j1, $client) = split(" ", $line);
				}
				when ($line =~ / reply /) {
					#reply star.c10r.facebook.com is 31.13.70.1
					($mon, $day, $time, $process, $action, $domain, $j1, $remote_ip) = split(" ", $line);
				}
				when ($line =~ / forwarded /) {
					#forwarded graph.facebook.com to 209.18.47.61
					($mon, $day, $time, $process, $action, $domain, $j1, $remote_dns) = split(" ", $line);
				}
				when ($line =~ / query\[TXT\] /) {
					#query[TXT] current.cvd.clamav.net from 192.168.1.102
					($mon, $day, $time, $process, $action, $domain, $j1, $client) = split(" ", $line);
				}
				when ($line =~ / cached /) {
					# ignore for now
					next;
				}
				when ($line =~ / query\[(?:NS|SOA|DNSKEY|type=(?:43|0)|SRV|ANY)\] /) {
					# ignore for now
					next;
				}
				when ($line =~ / query\[MX\] /) {
					# ignore for now
					next;
				}
				when ($line =~ / query\[PTR\] /) {
					# ignore for now
					next;
				}
				when ($line =~ / \/etc\/hosts /) {
					# ignore for now
					next;
				}
				# These should all be system messages regarding process specific stuff.  Maybe
				# create ani option later to dump these just to be sure.
				when ($line =~ / (?:started\,?|reading|exiting|ignoring|compile time|using nameserver|config) /) { next; }
				default {
					print $line."\n";
					next;
				}
			}
			$domains{$domain}++;
			next if ($domain =~ /^\.$/);
			my @parts = split(/\./, $domain);
			my $tld = $parts[-1];
			if ($tld =~ /[^a-zA-Z]+/) {
				if (($tld =~ /^\d+$/) && (($tld >= 0) && ($tld <= 255))) {
					#print STDERR "Likely an unresolved IP. \n";		# deal with this later
				} else {
					if ($verbose) {
						warn colored("[!!] Unexpected characters in TLD.", "bold yellow");
						print STDERR colored("TLD=$tld \n", "yellow");
					}
				}
			} else {
				unless (length($tld) > 5) { 
					$tlds{$tld}++;
					if ((defined($parts[-2])) && ($parts[-2] ne '')) {
						$ttdomains{"$parts[-2].$parts[-1]"}++;
					} else {
						print STDERR colored("[!!] Part 2 missing or blank: $line \n", "bold yellow") if ($verbose);
					}
				}
			}
		}
	} else {
		die colored("[EE] There was a problem with the input file ($ARGV[0]): $! \n", "bold red");
	}
} else {
	die colored("[EE] You need to specify a dns log to parse as an argument! \n", "bold red");
}

if ($dump) {
	open OUT, ">$dump" or die colored("Couldn't open dump file ($dump) for writing: $! \n", "bold red");
	foreach my $d ( sort %ttdomains ) {
		next if (exists($whitelist{$d}));
		next if ($d =~ /^\d+$/);
		print OUT "$d\n";
	}
	close OUT or die colored("Couldn't close dump file ($dump): $! \n", "bold red");
	exit 0;	
}

my $i = 0;
if (scalar(keys(%xfers)) > 0) {
	print STDERR colored("[!!] There was at least 1 zone transfer attempt from: \n", "bold magenta");
	print STDERR color("bold magenta");
	foreach my $x ( sort { $xfers{$b} <=> $xfers{$a} } keys %xfers ) {
		printf "[!!] %32s %-9d \n", $x, $xfers{$x};
	}
	print STDERR color("reset");
}

if ($show_tlds) {
	print colored("[**] Found the following unique top-level domains: \n", "bold cyan");
	if ($top) {
		@sorted = sort { $tlds{$b} <=> $tlds{$a} } keys %tlds;
	} else {
		@sorted = sort { $tlds{$a} <=> $tlds{$b} } keys %tlds;
	}
	foreach my $t ( @sorted ) {
		if ($threshold) { next unless ($tlds{$t} <= $threshold); }
		printf "[**] %32s %-9d \n", $t, $tlds{$t};
		last if (($depth) && ($i == $depth));
		$i++;
	}
}

$i = 0;
if ($top) {
	@sorted = sort { $ttdomains{$b} <=> $ttdomains{$a} } keys %ttdomains;
} else {
	@sorted = sort { $ttdomains{$a} <=> $ttdomains{$b} } keys %ttdomains;
}
print colored("[**] Found the following unique primary domains: \n", "bold cyan");
foreach my $t ( @sorted ) {
	if ($threshold) { next unless ($ttdomains{$t} <= $threshold); }
	if ($whitelist) { next if (exists($whitelist{$t})); }
	printf "[**] %32s %-9d \n", $t, $ttdomains{$t};
	last if (($depth) && ($i == $depth));
	$i++;
}

###############################################################################
###		Subs
###############################################################################
sub show_help() {
	print <<EoS;

$0 [OPTIONS] /path/to/dns/log 

Where:

-h|--help			Displays this helpful message.
-v|--verbose			Shows extra output messages.  Specify more times to increase verbosity.
-d|--depth			Specify the Top/Bottom number of results.
-t|--threshold			Specify all results above/below the specified repetition count.
-w|--whitelist			Specifies a list of accepted domains to ignore.  File should be
				one entry per line.
--show-tlds			Show TLDs within specified/default depth/threshold, in addition to the
				primary domains found.
--top				Show the top X items rather than the bottom
--bottom			Show the bottom X items.  This is the default.
--dump <filename>		Dumps unique DNS domain names (Tier-2) to the 
					specified file./


EoS

	exit 0;
}

sub load_whitelist() {
	my $wl = shift(@_);
	my %wl;

	if ((-e $wl) && (!-z $wl)) {
		open WL, $wl or die colored("Couldn't open whitelist file ($wl) for processing: $! \n", "bold red");
		while (my $line = <WL>) {
			chomp($line);
			$wl{$line}++;
		}
		close WL or die colored("Coudln't close whitelist file ($wl): $! \n", "bold red");
	} else {
		die colored("There was a problem with the whitelist file ($wl).  It does not exist or is zero bytes. \n", "bold red");
	}

	return %wl;
}

