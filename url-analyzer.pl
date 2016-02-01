#!/usr/bin/perl -w

use strict;
use warnings;
use feature qw( switch );
no if $] >= 5.017011, warnings => 'experimental::smartmatch';
use Term::ANSIColor;
use Data::Dumper;
use Getopt::Long;
use MIME::Base64;

my ($help, $verbose);

GetOptions(
	'h|help'		=>	\$help,
	'v|verbose+'	=>	\$verbose,
);

my (%mime_types, %cache_obj_requests);

if ($help) { &show_help(); }

# expects squid access.log as input
if ((defined($ARGV[0])) && ($ARGV[0] ne "")) {
	if (( -e $ARGV[0] ) && (! -z $ARGV[0])) {
		open IN, $ARGV[0] or die colored("[EE] Couldn't open input file ($ARGV[0]): $! \n", "bold red");
		while (my $line = <IN>) {
			chomp($line);
			#0397706.395     40 192.168.1.10 TCP_MISS/202 478 POST http://telemetry.battle.net/api/submit - ORIGINAL_DST/24.105.29.23 application/json
			my ($udate, $j1, $client, $cache_status, $j2, $http_action, $url, $j3, $j4, $mime_type) = split(" ", $line);
			$mime_types{$mime_type}++ if ((defined($mime_type)) && ($mime_type ne ''));
			if ($verbose) { print colored("[++] |$url| \n", "bold cyan"); }
			if ($url =~ /^(https?):\/\/([a-zA-Z0-9.-]+)\/(.*)/) {
				my $proto = $1; my $svr = $2; my $params = $3; 
				if ($verbose) {
					print qq/
[++]	PROTO:		$proto
[++]	SERVER:		$svr
[++]	QPATH:		$params
					/; print "\n";
				}
				if ($params =~ /[\&\?]/) { 
					if (($verbose) && ($verbose > 1)) { print colored("[**] Parsable parameters in query section! \n", "green"); }
					my ($ac, $ps) = split(/\?/, $params);
					if ($verbose) {
						print qq/
[++]	ACTION_SCRIPT:		$ac
[++]	PARAMS:			$ps
						/; print "\n";
					}
					if ((defined($ps)) && ($ps ne '')) {
						my @params = split(/\&/, $ps);
						if (($verbose) && ($verbose > 1)) { print Dumper(@params); }
						foreach my $kp ( sort @params ) {
							my ($key, $val) = split(/=/, $kp);
							if (((defined($val)) && ($val ne '')) && ($val =~ /([a-zA-Z0-9]+(?:\%3D|=(?:\%3D|=)?))$/)) {
								print "[**] Value appears to contain base64. \n";
								$val =~ s/\%3D/=/g;
								my $decoded = decode_base64($val);
								if ($decoded =~ /[^a-zA-Z0-9.-_]+/) {
									my @chars = split(//, $decoded);
									print "[%%] $key ==> ";
									foreach my $chr ( @chars ) { printf("\\x%x", ord($chr)); }
									print " \n";
								} else {
									print "[%%] $key ==> $decoded \n";
								}
							} 
						}
					} else {
						warn colored("[!!] The params section was empty! \n", "bold yellow");
					}
				} elsif ($params =~ /.*(?:%3D|=(?:%3D|=)?)$/) {
					print "[**] Value appears to contain base64. \n";
					$params =~ s/\%3D/=/g;
					my $decoded = decode_base64($params);
					if ($decoded =~ /[^a-zA-Z0-9.-_]+/) {
						my @chars = split(//, $decoded);
						print "[%%] ";
						foreach my $chr ( @chars ) { printf("\\x%X", ord($chr)); }
						print " \n";
					} else {
						print "[%%] $decoded \n";
					}
				} else {
					print colored("[##] $params \n", "bold blue");
				}
			} else {
				given ($url) {
					when (/^cache_object:\/\/([0-9.]+)\/(.*?)/) {
						$cache_obj_requests{$1}{$2}++;
					}
					default {
						print STDERR colored("[EE] Didn't match the URL regex! \n", "bold red");
						print STDERR colored("[EE] $url \n", "bold red");
					}
				}
			}
		}
	} else {
		die colored("[EE] There wa a problem with the file you specified.  It doesn't exist or is zero (0) bytes.\n", "bold red");
	}
} else {
	die colored("[EE] You must speficy a cache access log file to analyze.  \n", "bold red");
}

###############################################################################
###  Subs
###############################################################################
sub show_help() {
	print <<EoS;

$0 [-h|--help] [-v|--verbose] /path/to/squid/access/log

Where:

-h|--help           Displays this helpful message.
-v|--verbose        Shows extra output messages.  Specify more times to increase verbosity.

EoS

	exit 0;
};

