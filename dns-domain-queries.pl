#!/usr/bin/perl -w


use strict;
use warnings;
use Term::ANSIColor;
use Data::Dumper;
use Getopt::Long;

my ($help, $verbose, $depth, $threshold, $show_tlds, $whitelist, $show_mime_types);
$depth = 10;
$threshold = 10;
$verbose = 0;
$help = 0;
$show_tlds = 0;
$show_mime_types = 0;
GetOptions(
	"h|?|help"			=>	\$help,
	"v|verbose+"		=>	\$verbose,
	"d|depth=s"			=>	\$depth,
	"t|threshold=s"		=>	\$threshold,
	"show-tlds"			=>	\$show_tlds,
	"show-mime-types"	=>	\$show_mime_types,
	"w|whitelist=s"		=>	\$whitelist,
);

my (%tlds, %ttdomains, %domains, %mime_types, %whitelist);

if ($help) { &show_help(); }

if ($whitelist) { %whitelist = &load_whitelist($whitelist); }

if ((defined($ARGV[0])) && ($ARGV[0] ne "")) {
	if (( -e $ARGV[0] ) && (! -z $ARGV[0])) {
		open IN, $ARGV[0] or die "Couldn't open input file ($ARGV[0]): $! \n";
		while (my $line = <IN>) {
			chomp($line);
			my ($mon, $day, $time, $process, $action $domain $j1 $client);
			given ($line) {
				when ($line =~ /query\[A+\]/) {
					#Jan 16 00:38:55 dnsmasq[2349]: query[A] ssw.live.com from 192.168.1.135
					($mon, $day, $time, $process, $action $domain $j1 $client) = split(" ", $line);
				}
				default {
					print $line."\n";
				}
			}
			if ($url =~ /https?:\/\/(.*?)\//) {
				my $d = $1; $domains{$d}++;
				my @parts = split(/\./, $d);
				my $tld = $parts[-1];
				#print STDERR colored("URL=$url \n", "magenta");
				#print "SCALAR: ".scalar(@parts)."  \$\#: ".$#parts." \n";
				#print "-2: ".$parts[-2]."  -1: ".$parts[-1]." \n";
				if ($tld =~ /[^a-zA-Z]+/) {
					if (($tld =~ /^\d+$/) && (($tld >= 0) && ($tld <= 255))) {
						#print STDERR "Likely an unresolved IP. \n";		# deal with this later
					} else {
						if ($verbose) {
							warn colored("Unexpected characters in TLD.", "bold yellow");
							print STDERR colored("URL=$url \n", "yellow");
							print STDERR colored("TLD=$tld \n", "yellow");
						}
					}
				} else {
					unless (length($tld) > 5) { 
						$tlds{$tld}++;
						if ((defined($parts[-2])) && ($parts[-2] ne '')) {
							$ttdomains{"$parts[-2].$parts[-1]"}++;
						} else {
							print STDERR colored("Part 2 missing or blank: $line \n", "bold yellow") if ($verbose);
						}
					}
				}
			} elsif ($url =~ /^cache_object/) {
				# do nothing for now
			} elsif ($url =~ /^error:invalid-request/) {
				# still do nothing, but this will be interesting later, maybe
			} else { 
				if ($verbose) { warn colored("URL didn't match domain regex: $url \n", "bold yellow"); }
			}
		}
	} else {
		die colored("There was a problem with the input file ($ARGV[0]): $! \n", "bold red");
	}
} else {
	die colored("You need to specify a cache log to parse as an argument! \n", "bold red");
}

my $i = 0;
if ($show_tlds) {
	print colored("Found the following unique top-level domains: \n", "bold cyan");
	foreach my $t ( sort { $tlds{$a} <=> $tlds{$b} } keys %tlds ) {
		if ($threshold) { next unless ($tlds{$t} <= $threshold); }
		printf "%32s %-9d \n", $t, $tlds{$t};
		last if (($depth) && ($i == $depth));
		$i++;
	}
}

$i = 0;
if ($show_mime_types) {
	print colored("Found the following unique mime types: \n", "bold cyan");
	foreach my $mt ( sort { $mime_types{$a} <=> $mime_types{$b} } keys %mime_types ) {
		if ($threshold) { next unless ($mime_types{$mt} <= $threshold); }
		printf "%32s %-9d \n", $mt, $mime_types{$mt};
		last if (($depth) && ($i == $depth));
		$i++;
	}
}

$i = 0;
print colored("Found the following unique primary domains: \n", "bold cyan");
foreach my $t ( sort { $ttdomains{$a} <=> $ttdomains{$b} } keys %ttdomains ) {
	if ($threshold) { next unless ($ttdomains{$t} <= $threshold); }
	if ($whitelist) { next if (exists($whitelist{$t})); }
	printf "%32s %-9d \n", $t, $ttdomains{$t};
	last if (($depth) && ($i == $depth));
	$i++;
}

###############################################################################
###		Subs
###############################################################################
sub show_help() {
	print <<EoS;

$0 [-h|--help] [-v|--verbose] [-d|--depth] <integer> [-t|--threshold] <integer> [-w|--whitelist] </path/to/whitelist> --show-tlds

Where:

-h|--help			Displays this helpful message.
-v|--verbose		Shows extra output messages.  Specify more times to increase verbosity.
-d|--depth			Specify the Top/Bottom number of results.
-t|--threshold		Specify all results above/below the specified repetition count.
-w|--whitelist		Specifies a list of accepted domains to ignore.  File should be
					one entry per line.
--show-tlds			Show TLDs within specified/default depth/threshold, in addition to the
					primary domains found.

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
