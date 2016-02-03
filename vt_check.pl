#!/usr/bin/perl

use strict;
use warnings;
use Term::ANSIColor;
use Data::Dumper;
use URI::Encode qw( url_encode url_decode );

open KEY, "api.key" or die colored("Couldn't open api.key for reading: $! \n", "bold red");
my $apikey = <KEY>;
chomp($apikey);
close KEY or die colored("There was a problem closing the api.key: $! \n", "bold red");

my $vt_url = "https://www.virustotal.com/vtapi/v2/domain/report";
my $domain = $ARGV[0];
chomp($domain);
$domain = url_encode($domain);
print colored("[::] Domain: $domain \n", "bold yellow");

my %params = (
	'domain'	=>	"$domain",
	'apikey'	=>	"$apikey"
);

my $json = encode_json(\%params);

print Dumper($url, $json);
