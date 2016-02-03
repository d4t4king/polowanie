#!/bin/bash

echo "Installing perl modules from source, and in the required order."
echo "If you encounter any errors or problems, and don't know what to do, post on the SWE forums, in the thread for this script."

cd
perl -mDigest::HMAC -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/G/GA/GAAS/Digest-HMAC-1.03.tar.gz
	tar xf Digest-HMAC-1.03.tar.gz
	cd Digest-HMAC-1.03/
	perl Makefile.PL
	make && make install
fi
cd
perl -mNet::DNS -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/N/NL/NLNETLABS/Net-DNS-0.80.tar.gz
	tar xf Net-DNS-0.80.tar.gz
	cd Net-DNS-0.80/
	perl Makefile.PL
	make && make install
fi
cd
perl -mNet::Nslookup -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/D/DA/DARREN/Net-Nslookup-2.01.tar.gz
	tar xf Net-Nslookup-2.01.tar.gz
	cd Net-Nslookup-2.01/
	perl Makefile.PL
	make && make install
fi
cd
perl -mGeo::IP::PurePerl -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/B/BO/BORISZ/Geo-IP-PurePerl-1.25.tar.gz
	tar xf Geo-IP-PurePerl-1.25.tar.gz
	cd Geo-IP-PurePerl-1.25/
	perl Makefile.PL
	make && make install
fi
cd
perl -mNet::IPv4Addr -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/F/FR/FRAJULAC/Net-IPv4Addr-0.10.tar.gz
	tar xf Net-IPv4Addr-0.10.tar.gz
	cd Net-IPv4Addr-0.10/
	perl Makefile.PL
	make && make install
fi
cd
perl -mSub::Uplevel -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/D/DA/DAGOLDEN/Sub-Uplevel-0.24.tar.gz
	tar xf Sub-Uplevel-0.24.tar.gz
	cd Sub-Uplevel-0.24/
	perl Makefile.PL
	make && make install
fi
cd
perl -mTest::Exception -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/E/EX/EXODIST/Test-Exception-0.35.tar.gz
	tar xf Test-Exception-0.35.tar.gz
	cd Test-Exception-0.35/
	perl Makefile.PL
	make && make install
fi
cd
perl -mCarp::Clan -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/S/ST/STBEY/Carp-Clan-6.04.tar.gz
	tar xf Carp-Clan-6.04.tar.gz
	cd Carp-Clan-6.04/
	perl Makefile.PL
	make && make install
fi
cd
perl -mBit::Vector -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/S/ST/STBEY/Bit-Vector-7.3.tar.gz
	tar xf Bit-Vector-7.3.tar.gz
	cd Bit-Vector-7.3/
	perl Makefile.PL
	make && make install
fi
cd
perl -mDate::Calc -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/S/ST/STBEY/Date-Calc-6.3.tar.gz
	tar xf Date-Calc-6.3.tar.gz
	cd Date-Calc-6.3/
	perl Makefile.PL
	make && make install
fi
cd
perl -mConfig::Simple -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/S/SH/SHERZODR/Config-Simple-4.59.tar.gz
	tar xf Config-Simple-4.59.tar.gz
	cd Config-Simple-4.59
	perl Makefile.PL
	make && make install
fi
cd
perl -mMailTools -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/M/MA/MARKOV/MailTools-2.14.tar.gz
	tar xf MailTools-2.14.tar.gz
	cd MailTools-2.14
	perl Makefile.PL
	make && make install
fi
cd
perl -mMIME::Types -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/M/MA/MARKOV/MIME-Types-2.11.tar.gz
	tar xf MIME-Types-2.11.tar.gz
	cd MIME-Types-2.11
	perl Makefile.PL
	make && make install
fi
cd
perl -mMIME::Lite -e ';' > 2/dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/R/RJ/RJBS/MIME-Lite-3.030.tar.gz
	tar xf MIME-Lite-3.030.tar.gz
	cd MIME-Lite-3.030
	perl Makefile.PL
	make && make install
fi
cd
# The following are requirements or sub-requirements for Net::Whois::Parser
perl -mNet::Whois::Parser -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/E/EX/EXODIST/Test-Simple-1.001014.tar.gz
	wget http://search.cpan.org/CPAN/authors/id/A/AD/ADAMK/Test-NoWarnings-1.04.tar.gz
	wget http://search.cpan.org/CPAN/authors/id/C/CF/CFAERBER/Net-IDN-Encode-2.300.tar.gz
	wget http://search.cpan.org/CPAN/authors/id/P/PE/PEVANS/Socket-2.021.tar.gz
	wget http://search.cpan.org/CPAN/authors/id/P/PE/PEVANS/IO-Socket-IP-0.37.tar.gz
	wget http://search.cpan.org/CPAN/authors/id/S/SA/SALVA/Regexp-IPv6-0.03.tar.gz
	wget http://search.cpan.org/CPAN/authors/id/M/MA/MALLEN/Test-RequiresInternet-0.05.tar.gz
	wget http://search.cpan.org/CPAN/authors/id/N/NA/NALOBIN/Net-Whois-Raw-2.91.tar.gz
	wget http://search.cpan.org/CPAN/authors/id/I/IV/IVSOKOLOV/Net-Whois-Parser-0.05.tar.gz
	for TB in Test-Simple-1.001014 Test-NoWarnings-1.04 Net-IDN-Encode-2.300 Socket-2.021 IO-Socket-IP-0.37 Regexp-IPv6-0.03 Test-RequiresInternet-0.05 Net-Whois-Raw-2.91 Net-Whois-Parser-0.05;
	do
		tar xf ${TB}.tar.gz
		cd ${TB}
		perl Makefile.PL
		make && make install
		cd ..
	done
fi
cd
perl -mURL::Encode -e ';' > /dev/null 2>&1
if [ ! $? == 0 ]; then
	wget http://search.cpan.org/CPAN/authors/id/B/BI/BINGOS/ExtUtils-MakeMaker-7.10.tar.gz
	wget http://search.cpan.org/CPAN/authors/id/C/CH/CHANSEN/URL-Encode-0.03.tar.gz
	for TB in ExtUtils-MakeMaker-7.10 URL-Encode-0.03; do
		tar xf ${TB}.tar.gz
		cd ${TB}
		perl Makefile.PL
		make && make install
		cd ..
	done
fi

rm -rf Digest* ExtUtils* Net* Geo-IP* Sub* Carp* Bit* Date* Config* Mail* MIME* IO* Socket* Regexp* Test* URL*

mkdir -p /var/smoothwall/mods/polowanie
touch /var/smoothwall/mods/polowanie/installed

if [[ -e && !-z /etc/dnsmasq.conf ]]; then
	echo "It looks like the custom dnsmasq config has already ben created.  Or, "
	echo "you've done some customizations of your own.  Either way, it looks like "
	echo "you should know whether dnsmasq is logging or not.  If you're not sure, "
	echo "manually verify that /etc/dnsmasq.conf contains the following:  "
	echo
	echo "log-queries"
	echo "log-facility=\"/var/log/dns.log\""
	echo
	echo "...and that /var/log/dns.log is owned and writeable by nobody."
	if [[ -e /var/log/dns.log ]]; then
		chown nobody:nobody /var/log/dns.log
	fi
fi

