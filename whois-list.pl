#!/usr/bin/perl -w 

use strict;
use warnings;
use feature qw( switch );
#no warnings "experimental::smartmatch";
use Term::ANSIColor;
use Data::Dumper;
use Getopt::Long;
use Net::Whois::Parser;
use LWP::Simple qw( get getstore );
use LWP::UserAgent;
use File::Find;
use URL::Encode qw( url_encode url_decode );
use JSON;

my ($help, $reason, $outfile, $update_file);
our $verbose;
our @f_to_process;
$verbose = 0;
$reason = 0;
GetOptions(
	'h|help'			=> \$help,
	'v|verbose+'		=> \$verbose,
	'r|reason'			=> \$reason,
	'u|update-file=s'	=> \$update_file,
	'o|out=s'			=> \$outfile,
);

our %bad_countries = (
	'CN'	=>	1,
	'RU'	=>	1,
	'BR'	=>	1,
	'KZ'	=>	1,
	'TU'	=>	1,
	'IR'	=>	1,
);

if ($help) { &show_help(); }

my %registrars = &load_registrars;

my %shalla = &get_shalla_blacklist("/tmp");

#print Dumper(%shalla);
#exit 1;

open IN, "<$ARGV[0]" or die colored("Couldn't open input file ($ARGV[0]) for reading: $!", "bold red");
if ($outfile) { open OUT, ">$outfile" or die colored("Couldn't open output file for writing: $!", "bold red"); }
while (my $domain = <IN>) {
	chomp($domain);
	$domain = lc($domain);
	print colored("[>>] Domain: $domain \n", "bold green");
	#print Dumper($w);
	my $wout = `whois $domain 2>&1`;
	#print "$wout \n";
	my $score = &get_reliability_score($wout, $domain, $reason);
	# maybe not do this???????
	if ($score == 0) {
		print "[**] ====================================================================\n";
		next;
	}
	# shalla check
	if (exists($shalla{$domain})) { 
		$score *= .4;
		if ($reason) { print colored("  [::] Domain in Shalla black list.  -60%. \n", "bold yellow"); }
	}
	# vt check
	my $webrep = &do_vt_lookup($domain);
	if ((defined($webrep->{'Verdict'})) && ($webrep->{'Verdict'} ne '')) {
		if ($webrep->{'Verdict'} eq 'safe') {
			$score *= 1.5;
			if ($reason) { print colored("  [::] Domain considered \"safe\" by VirusTotal.  +50% \n", "bold yellow"); }
		} else {
			if ($verbose) { print colored("  [##] VT Verdict was something other than safe ($webrep->{'Verdict'}). \n", "cyan"); }
		}
	} else {
		warn colored("[!!] Verdict field was empty!", "yellow");
	}
	print colored("[>>] Webutation safety score: $webrep->{'Safety score'} \n", "bold green");
	print colored("[>>] Reliability Score: $score \n", "bold green");
	if ($update_file) {
		if ($score >= 100) {
			open WL, ">>$update_file" or die colored("Couldn't append to whitelist file ($update_file): $!", "bold red");
			print WL "$domain\n";
			close WL or die colored("Couldn't close whitelist file: $!", "bold red");
		}
	}
	print "[**] ====================================================================\n";
	if ($outfile) { print OUT "$domain|$score\n"; }
	#print "[**] Press ENTER to continue..... \n";
	#<STDIN>;
	sleep(5);
}
if ($outfile) { close OUT or die colored("Unable to close output file ($outfile): $!", "bold red"); }
close IN or die colored("Couldn't close input file: $!", "bold red");

###############################################################################
### Subroutines
###############################################################################
sub get_reliability_score() {
	my $raw_whois_text = shift(@_);
	my $domain = lc(shift(@_));
	my $show_reason = shift(@_);
	my $score = 100;
	my $whois_obj = parse_whois( raw => $raw_whois_text, domain => $domain );
	my $assessment_country = '';
	if (defined($whois_obj->{'tech_country'}) && ($whois_obj->{'tech_country'} ne "")) {
		# for now let's assum they use ALL shorthand or ALL long hand
		if ($whois_obj->{'tech_country'} eq $whois_obj->{'admin_country'}) {
			$assessment_country = $whois_obj->{'tech_country'};
		} else {
			# not sure what else to do here, so die
			if ($reason){ 
				if ($verbose) {
					print Dumper($whois_obj);
				}
			}
			#die colored("Technical and administrative contact countries didn't match!  (T: $whois_obj->{'tech_country'} A: $whois_obj->{'admin_country'} \n", "bold red");
			$score *= .95;
			if ($reason) { print colored("  [::] Tech and admin countries don't match.  -5%. \n", "bold yellow"); }
		}
	} elsif ((defined($whois_obj->{'technical_contact_country_code'})) && ($whois_obj->{'technical_contact_country_code'} ne "")) { 
		if ($whois_obj->{'technical_contact_country_code'} eq $whois_obj->{'administrative_contact_country_code'}) {
			$assessment_country = $whois_obj->{'technical_contact_country_code'};
		} else {
			# not sure what else to do here, so die
			#print Dumper($whois_obj);
			#die colored("Technical and administrative contact countries didn't match!  (T: $whois_obj->{'technical_contact_country_code'} A: $whois_obj->{'administrative_contact_country_code'} \n", "bold red");
			$score *= .95;
			if ($reason) { print colored("  [::] Tech and admin email domains don't match.  -5%. \n", "bold yellow"); }
		}
	} else {
		if ((defined($whois_obj->{'terms_of_use'})) && ($whois_obj->{'terms_of_use'} ne "")) {
			if ($whois_obj->{'terms_of_use'} =~ /You are not authorized to access or query our Whois/) {
				if ($reason) {
					if ($verbose) { 
						print colored("[!!] Domain likely not found! ($domain) \n", "yellow");
					}
				}
				return 0;
			}
		} else {
			#die colored("[EE] Couldn't find expected long or short hand. \n".Dumper($whois_obj), "bold red");
			if ($reason) { print colored("  [::] Not enough data to make evaluation.  Score zeroized. \n", "bold yellow"); }
			return 0;
		}
	}
	if ($verbose) { print colored("  [++] Country: $assessment_country \n", "bold yellow"); }
	if (exists($bad_countries{$assessment_country})) { 
		$score *= .5;
		if ($reason) { print colored("  [::] Assessment country in active countries list.  -50% \n", "bold yellow"); }
	}
	# Should be true or false.  'Unsigned' seems to be a valid value also.
	if (defined($whois_obj->{'dnssec'})) {
		if ($whois_obj->{'dnssec'} eq 'true') { 
			$score *= 2; 
			if ($reason) { print colored("  [::] DNSSEC is true.  +100% \n", "bold yellow"); }
		} elsif ($whois_obj->{'dnssec'} eq 'Unsigned') {
			$score *= 1.25;
			if ($reason) { print colored("  [::] DNSSEC supported but not signed.  +25% \n", "bold yellow"); }
		}
	} else {
		if ($reason) { print colored("[!!] DNSSEC field not defined. \n", "yellow"); }
	}
	my ($tech_email_dom,$admin_email_dom);
	if ((defined($whois_obj->{'technical_contact_email'})) && ($whois_obj->{'technical_contact_email'} ne "")) {
		$tech_email_dom = lc((split(/\@/, $whois_obj->{'technical_contact_email'}))[1]);
	} elsif ((defined($whois_obj->{'tech_email'})) && ($whois_obj->{'tech_email'} ne "")) {
		$tech_email_dom = lc((split(/\@/, $whois_obj->{'tech_email'}))[1]);
	}
	if ($tech_email_dom ne $domain) { 
		$score *= .9; 
		if ($reason) { print colored("  [::] Tech email domain ($tech_email_dom) does not equal query domain ($domain).  -10% \n", "bold yellow"); }
	}
	if ((defined($whois_obj->{'administrative_contact_email'})) && ($whois_obj->{'administrative_contact_email'} ne "")) {
		$admin_email_dom = lc((split(/\@/, $whois_obj->{'administrative_contact_email'}))[1]);
	} elsif ((defined($whois_obj->{'admin_email'})) && ($whois_obj->{'admin_email'} ne "")) {
		$admin_email_dom = lc((split(/\@/, $whois_obj->{'admin_email'}))[1]);
	}
	if ($admin_email_dom ne $domain) { 
		$score *= .9; 
		if ($reason) { print colored("  [::] Admin email domain ($admin_email_dom) does not equal query domain ($domain).  -10% \n", "bold yellow"); }
	}
	if (defined($whois_obj->{'registrar'})) {
		if (exists($registrars{lc($whois_obj->{'registrar'})})) {
			$score *= $registrars{lc($whois_obj->{'registrar'})};
			if ($reason) { print colored("  [::] Registrar in known list.  ".sprintf("%3.2f%%", ($registrars{lc($whois_obj->{'registrar'})} * 100))." of total so far. \n", "bold yellow"); }
		} else {
			print Dumper($whois_obj);
			die colored("[!!] Registrar not in list: |$whois_obj->{'registrar'}|", "bold red");
		}
	} elsif (defined($whois_obj->{'sponsoring_registrar'})) {
		if (exists($registrars{lc($whois_obj->{'sponsoring_registrar'})})) {
			$score *= $registrars{lc($whois_obj->{'sponsoring_registrar'})};
			### FIX ME!!!  There should be a deduction for sponsoring registrar.  This means that someone outside of InterNIC is registering an InterNIC TLD.
			if ($reason) { print colored("  [::] Registrar in known list.  ".sprintf("%3.2f%%", ($registrars{lc($whois_obj->{'sponsoring_registrar'})} * 100))." of total so far. \n", "bold yellow"); }
		} else {
			print Dumper($whois_obj);
			die colored("[!!] Registrar not in list: |$whois_obj->{'sponsoring_registrar'}|", "bold red");
		}
	} else {
		#print Dumper($whois_obj);
		#die colored("[EE] Registrar not listed. \n", "bold red");
		$score *= .5;
		if ($reason) { print colored("  [::] Registrar not defined.  -50% ", "bold yellow"); }
	}
	return sprintf("%-4.4f", $score);
}

sub show_help {
	print <<EoS;

$0 [OPTIONS] domains-list-input.txt 

-h|--help				Displays this useful message then exits
-v|--verbose				Adds extra output that might be useful for debugging
-r|--reason				Displays the reasoning for score adjustments as 
					adjustments are made for each domain.
-o|--outfile				Outputs a simple report consisting of the domain
					and its score, separated by a pipe (|).
-u|--update-file			Whitelist file to update.  You should probably only
					use this, if you know what you're doing.


EoS
	exit 0;
}

sub load_registrars {
	my %reg;
	open REGIN, "<.registrars.dat" or die colored("[EE] There was a problem open the registrars database file: $! ", "bold red");
	while (my $r = <REGIN>) {
		chomp($r);
		my ($n,$s) = split(":", $r);
		$reg{$n} = $s;
	}
	close REGIN or die colored("[EE] There was a problem closing the registrars database file: $! ", "bold red");
	return %reg;
}

sub download_blacklist {
	my $url = shift(@_);
	my $filename = $url;
	$filename =~ /.*\/(.*)$/;
	$filename = $1;
	my $ua = LWP::UserAgent->new();
	my $resp = $ua->get($url);
	unless ($resp->is_success) { die colored("$resp->status_line", "bold red"); }
	my $save = "/tmp/$filename";
	getstore($url, $save);
	my $rtv = system("tar xf $save -C /tmp/ > /dev/null 2>&1");
	return $rtv;
}

sub get_shalla_blacklist {
	my $path = shift(@_);
	# check path for 'BL\" directory
	unless (-d "$path/BL") {
	# unless exists
	# 	download and extract the file
		my $rtv = &download_blacklist("http://www.shallalist.de/Downloads/shallalist.tar.gz");
		print STDERR colored("RTV: $rtv \n", "bold yellow");
	# end
	}
	# File::Find "BL/*/domains"
	find(\&wanted, "$path/BL");
	my %bl_domains;
	foreach my $file ( @f_to_process ) {
		open IN, "<$file" or die colored("Couldn't open input file ($file) for processing: $!", "bold red");
		while (my $line = <IN>) {
			chomp($line);
			# next if IP	(maybe do something with them later?????
			#next if ($line =~ /^\d+\.\d+\.\d+\.\d+$/);
			# $hash{$domain}++
			$bl_domains{$line}++;
		}
		close IN or die colored("There was a problem closing the input file ($file): $!", "bold red");
	}
	# return %hash
	return %bl_domains;
}

sub wanted {
	if ((! -z ) && ($_ eq 'domains')) {
		if ($File::Find::dir =~ /(?:anonvpn|porn|remotecontrol|sex|spyware|tracker|urlshortener|warez)$/) {
			push @f_to_process, $File::Find::name;
		} else {
			if (($verbose) && ($verbose > 1)) {
				print colored("[##] Didn't match BL: $File::Find::dir \n", "yellow");
			}
		}
	}
}

sub get_vt_apikey {
	unless ( -e "api.key" ) { die colored("Unable to find the api.key file for VT processing!", "bold red"); }
	open KEY, "<api.key" or die colored("Can't open api.key: $!", "bold red");
	my $apikey = <KEY>;
	chomp($apikey);
	close KEY or die colored("There was a problem closing the api.key file: $!", "bold red");
	return $apikey;
}

sub do_vt_lookup {
	my $domain = shift(@_);
	my $apikey = &get_vt_apikey();
	my $vt_url = "https://www.virustotal.com/vtapi/v2/domain/report";
	my $content = get("$vt_url?domain=$domain&apikey=$apikey");
	$content = decode_json($content);
	sleep(10);
	return $content->{'Webutation domain info'};
}
