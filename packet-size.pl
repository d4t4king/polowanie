#!/usr/bin/perl -w

use strict;
use warnings;
use feature qw( switch );
#no warnings "experimental::smartmatch";
use Term::ANSIColor;
use Data::Dumper;
use Getopt::Long;
use POSIX;
use Date::Calc qw( Localtime );

my ($help, $verbose, $tcp, $udp);
$tcp = 0;
$udp = 0;
$verbose = 0;
GetOptions(
	"h|help"		=>	\$help,
	"v|verbose+"	=>	\$verbose,
	"tcp"			=>	\$tcp,
	"udp"			=>	\$udp,
);

my $not_syn = 0;
my $total_packets = 0;
my $first = 0;
my $last = 0;
my $time_diff = 0;
my %seqs;

if (($tcp) && ($udp)) {
	die colored("Can't operate on both TCP and UDP at this point in time. \n", "bold red");
}

my $count = 0;
my $infile = $ARGV[0] ? $ARGV[0] : "/var/log/messages";
print colored("Processing file: $infile \n", "bold yellow");
open IN, "$infile" or die colored("Couldn't open input file ($infile) for reading: $! \n", "bold red");
while (my $line = <IN>) {
	chomp($line);
	next unless ($line =~ /Denied-by-filter:/);
	if ($udp) { next unless ($line =~ /PROTO=UDP/); }
	if ($tcp) { next unless ($line =~ /PROTO=TCP/); }
	$total_packets++;
	if ($line =~ / SYN /) {
		#print "$line\n";
		my @parts = split(/\s+/, $line);
		my $epoch_date = &get_epoch_date($parts[0], $parts[1], $parts[2]);
		if ($count == 0) { $first = $epoch_date; }
		my ($srcip, $dstip, $len);
		if ($line =~ /SRC=([0-9.]+)/) { $srcip = $1; }
		else { warn colored("Couldn't match source IP in line! \n", "yellow"); }
		if ($line =~ /DST=([0-9.]+)/) { $dstip = $1; }
		else { warn colored("Couldn't match destination IP in line! \n", "yellow"); }
		if ($line =~ /LEN=([0-9]+)/) { $len = $1; } 
		else { warn colored("Couldn't match packet length in line! \n", "yellow"); }
		$seqs{$srcip}{$dstip}{$epoch_date} = $len;
		$count++;
		$last = $epoch_date;
	} else { $not_syn++; }
}
close IN, or die colored("Couldn't close input file ($infile): $! \n", "bold red");

#foreach my $src ( sort keys %seqs ) {
#	foreach my $dst ( sort keys %{$seqs{$src}} ) {
#		my $last_ed;
#		foreach my $ed ( sort keys %{$seqs{$src}{$dst}} ) {
#			my $diff = $ed - $last_ed;
#			print colored("Time diff:  $diff \n", "bold green");
#			$last_ed = $ed;
#		}
#	}
#}

END {
	$time_diff = $last - $first;
	my ($fy,$fm,$fd,$fH,$fM,$fS,$fdoy,$fdow,$fdst) = Localtime($first);
	my ($ly,$lm,$ld,$lH,$lM,$lS,$ldoy,$ldow,$ldst) = Localtime($last);
	my $days = int($time_diff / (24 * 60 * 60));
	my $hours = ($time_diff / (60 * 60)) % 24;
	my $mins = ($time_diff / 60) % 60;
	my $secs = $time_diff % 60;
	print colored("F: $first L: $last \n", "bold yellow");
	print colored("F: $fm/$fd/$fy $fH:$fM:$fS L: $lm/$ld/$ly $lH:$lM:$lS \n", "bold yellow");
	print colored("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n", "bold cyan");
	print colored("=-\tTotal packets encountered after filter: $total_packets \n", "bold cyan");
	print colored("=-\tBlocked Non-SYN packets: $not_syn \n", "bold cyan");
	print colored("=-\tTime different between first and last: $time_diff secs \n", "bold cyan");
	print colored("=-\tTime different between first and last: $days days, $hours hours, $mins mins, $secs secs \n", "bold cyan");
	print colored("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n", "bold cyan");
}

###############################################################################
### Subroutines
###############################################################################
sub show_help() {

}

sub get_epoch_date() {
	my $mon = shift(@_);
	my $mday = shift(@_);
	my $time = shift(@_);
	my ($hh, $mm, $ss) = split(/\:/, $time);
	my $monnum = &mon2num($mon);
	my @ltime = localtime();
	#print colored("Y: $ltime[5] M: $monnum D: $mday H: $hh M: $mm S: $ss \n", "bold yellow");
	#print colored(mktime($ss, $mm, $hh, $mday, $monnum, $ltime[5]) . "\n", "bold yellow");
	return mktime($ss, $mm, $hh, $mday, $monnum, $ltime[5]);
}

sub mon2num() {
	my $mon = shift(@_);

	given ($mon) {
		when (/Jan/) { return 0; }
		when (/Feb/) { return 1; }
		when (/Mar/) { return 2; }
		when (/Apr/) { return 3; }
		when (/May/) { return 4; }
		when (/Jun/) { return 5; }
		when (/Jul/) { return 6; }
		when (/Aug/) { return 7; }
		when (/Sep/) { return 8; }
		when (/Oct/) { return 9; }
		when (/Nov/) { return 10; }
		when (/Dec/) { return 11; }
		default { return undef; }
	}
}
