#!/usr/bin/perl -w 

use strict;
use warnings;
use Term::ANSIColor;
use Data::Dumper;
use Getopt::Long;
use Net::Whois::Parser;

my ($help, $verbose, $reason);
GetOptions(
	'h|help'		=> \$help,
	'v|verbose+'	=> \$verbose,
	'r|reason'		=> \$reason,
);

our %bad_countries = (
	'CN'	=>	1,
	'RU'	=>	1,
	'BR'	=>	1,
);
our %registrars = (
	"enom, inc."											=>	.75,
	"godaddy, inc."											=>	1,
	"godaddy.com, llc"										=>	1,
	"godaddy.com, inc."										=>	1,
	"godaddy.com, llc (146)"								=>	1,
	"network solutions, llc."								=>	1,
	"name.com, inc."										=> .85,
	"tucows, inc."											=>	1,
	"csc corporate domains, inc."							=>	1,
	"markmonitor, inc."										=>	1,
	"pairnic inc"											=>	1,
	"safenames ltd"											=>	1,
	"register.com, inc."									=>	1,
	"psi-usa, inc. dba domain robot"						=>	.75,
	"webfusion limited"										=>	1,
	"csl computer service langenbach gmbh d/b/a joker.com"	=>	.95,
	"gandi sas"												=>	1,
);

open IN, "<$ARGV[0]" or die colored("Couldn't open input file ($ARGV[0]) for reading: $! \n", "bold red");
while (my $domain = <IN>) {
	chomp($domain);
	#Net::Whois is very limited.
	#my $w = new Net::Whois::Domain $domain or die colored("Can't connect to Whois server. \n", "bold red");
	#unless ($w->ok) { warn colored("No match for $domain \n", "bold magenta"); }
	#print Dumper($w);
	my $wout = `whois $domain 2>&1`;
	#print "$wout \n";
	my $score = &get_reliability_score($wout, $domain);
	print colored("[>>] Domain: $domain \n", "bold green");
	print colored("[>>] Reliability Score: $score \n", "bold green");
	print "\n\n";
	if ($score >= 100) {
		open OUT, ">>cache-whitelist.txt" or die colored("Couldn't append to whitelist file: $! \n", "bold red");
		print OUT "$domain\n";
		close OUT or die colored("Couldn't close whitelist file: $! \n", "bold red");
	}
	print "[**] ====================================================================\n";
	print "[**] Press ENTER to continue..... \n";
	<STDIN>;
}
close IN or die colored("Couldn't close input file: $! \n", "bold red");

###############################################################################
### Subroutines
###############################################################################
sub get_reliability_score() {
	my $raw_whois_text = shift(@_);
	my $domain = lc(shift(@_));
	my $score = 100;
	my $whois_obj = parse_whois( raw => $raw_whois_text, domain => $domain );
	my $assessment_country = '';
	if (defined($whois_obj->{'tech_country'}) && ($whois_obj->{'tech_country'} ne "")) {
		# for now let's assum they use ALL shorthand or ALL long hand
		if ($whois_obj->{'tech_country'} eq $whois_obj->{'admin_country'}) {
			$assessment_country = $whois_obj->{'tech_country'};
		} else {
			# not sure what else to do here, so die
			print Dumper($whois_obj);
			die colored("Technical and administrative contact countries didn't match!  (T: $whois_obj->{'tech_country'} A: $whois_obj->{'admin_country'} \n", "bold red");
		}
	} elsif ((defined($whois_obj->{'technical_contact_country_code'})) && ($whois_obj->{'technical_contact_country_code'} ne "")) { 
		if ($whois_obj->{'technical_contact_country_code'} eq $whois_obj->{'administrative_contact_country_code'}) {
			$assessment_country = $whois_obj->{'technical_contact_country_code'};
		} else {
			# not sure what else to do here, so die
			print Dumper($whois_obj);
			die colored("Technical and administrative contact countries didn't match!  (T: $whois_obj->{'technical_contact_country_code'} A: $whois_obj->{'administrative_contact_country_code'} \n", "bold red");
		}
	} else {
		if ((defined($whois_obj->{'terms_of_use'})) && ($whois_obj->{'terms_of_use'} ne "")) {
			if ($whois_obj->{'terms_of_use'} =~ /You are not authorized to access or query our Whois/) {
				print colored("[!!] Domain likely not found! ($domain) \n", "yellow");
				return 0;
			}
		} else {
			die colored("[EE] Couldn't find expected long or short hand. \n".Dumper($whois_obj), "bold red");
		}
	}
	print colored("  [++] Country; $assessment_country \n", "bold yellow");
	if (exists($bad_countries{$assessment_country})) { 
		$score *= .5;
		print colored("  [::] Assessment country in active countries list.  -50% \n", "bold yellow");
	}
	# Should be true or false.  'Unsigned' seems to be a valid value also.
	if (defined($whois_obj->{'dnssec'})) {
		if ($whois_obj->{'dnssec'} eq 'true') { 
			$score *= 2; 
			print colored("  [::] DNSSEC is true.  +100% \n", "bold yellow");
		} elsif ($whois_obj->{'dnssec'} eq 'Unsigned') {
			$score *= 1.25;
			print colored("  [::] DNSSEC supported but not signed.  +25% \n", "bold yellow");
		}
	} else {
		print colored("[!!] DNSSEC field not defined. \n ".Dumper($whois_obj), "yellow");
	}
	my ($tech_email_dom,$admin_email_dom);
	if ((defined($whois_obj->{'technical_contact_email'})) && ($whois_obj->{'technical_contact_email'} ne "")) {
		$tech_email_dom = lc((split(/\@/, $whois_obj->{'technical_contact_email'}))[1]);
	} elsif ((defined($whois_obj->{'tech_email'})) && ($whois_obj->{'tech_email'} ne "")) {
		$tech_email_dom = lc((split(/\@/, $whois_obj->{'tech_email'}))[1]);
	}
	if ($tech_email_dom ne $domain) { 
		$score *= .9; 
		print colored("  [::] Tech email domain ($tech_email_dom) does not equal query domain ($domain).  -10% \n", "bold yellow");
	}
	if ((defined($whois_obj->{'administrative_contact_email'})) && ($whois_obj->{'administrative_contact_email'} ne "")) {
		$admin_email_dom = lc((split(/\@/, $whois_obj->{'administrative_contact_email'}))[1]);
	} elsif ((defined($whois_obj->{'admin_email'})) && ($whois_obj->{'admin_email'} ne "")) {
		$admin_email_dom = lc((split(/\@/, $whois_obj->{'admin_email'}))[1]);
	}
	if ($admin_email_dom ne $domain) { 
		$score *= .9; 
		print colored("  [::] Admin email domain ($admin_email_dom) does not equal query domain ($domain).  -10% \n", "bold yellow");
	}
	if (defined($whois_obj->{'registrar'})) {
		if (exists($registrars{lc($whois_obj->{'registrar'})})) {
			$score *= $registrars{lc($whois_obj->{'registrar'})};
			print colored("  [::] Registrar in known list.  ".sprintf("%3.2f%%", ($registrars{lc($whois_obj->{'registrar'})} * 100))." of total so far. \n", "bold yellow");
		} else {
			print colored("[!!] Registrar not in list: $whois_obj->{'registrar'} \n", "bold yellow");
			print Dumper($whois_obj);
		}
	} elsif (defined($whois_obj->{'sponsoring_registrar'})) {
		if (exists($registrars{lc($whois_obj->{'sponsoring_registrar'})})) {
			$score *= $registrars{lc($whois_obj->{'sponsoring_registrar'})};
			### FIX ME!!!  There should be a deduction for sponsoring registrar.  This means that someone outside of InterNIC is registering an InterNIC TLD.
			print colored("  [::] Registrar in known list.  ".sprintf("%3.2f%%", ($registrars{lc($whois_obj->{'sponsoring_registrar'})} * 100))." of total so far. \n", "bold yellow");
		} else {
			print colored("[!!] Registrar not in list: $whois_obj->{'sponsoring_registrar'} \n", "bold yellow");
			print Dumper($whois_obj);
		}
	} else {
		print Dumper($whois_obj);
		die colored("[EE] Registrar not listed. \n", "bold red");
	}
	return sprintf("%-4.4f", $score);
}
