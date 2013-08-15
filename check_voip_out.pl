#!/usr/bin/perl
use strict;
use warnings;
use Test::More;

my $qos;
my $pcap2payload;
my $payload = 'testfile.payload';

ok(system("sipp -sf ../sipp/uac.xml -inf ../sipp/user.csv sip.phone.com -r 1 -mi 10.128.7.112 -m 1 -s 18582240094 -d 15000") >> 8 eq 0, "SIPp call made");

$qos = `tshark -n -r /var/spool/pcapsipdump/20130812/20/20130812-202233-74918-18582240094-1-5720\@127.0.1.1.pcap -q -z rtp,streams`;
print "$qos \n";

$pcap2payload = `tshark -n -r /var/spool/pcapsipdump/20130812/20/20130812-202233-74918-18582240094-1-5720\@127.0.1.1.pcap -R rtp -T fields -e rtp.payload | tee $payload`;

rtp2wav();


## translate the ascii-hex payload from tshark to actual binary data
sub rtp2wav{
        open(MYFILE, "<", "testfile.payload")
                or die "cannot open < testfile.payload: $!";
        open(OUTFILE, ">", "testfile.raw");
        while(<MYFILE>) {
                my $line = $_;
                chop $line;
		my $char;
                foreach $char(split(/:/,$line)) {
                #       print chr(hex($char));
                        print OUTFILE chr(hex($char));
                }
        }
        close(MYFILE);
        close(OUTFILE);
	my $raw2wav;
	$raw2wav = `sox -t raw -r 8000 -c 1 -U testfile.raw testfile.wav`;
}

=head
if ($? == -1) {
    print "failed to execute: $!\n";
} elsif ($? & 127) {
    printf "child died - signal %d, %s coredump\n",
           ($? & 127), ($? & 128) ? 'with' : 'without';
} else {
    printf "child exited with value %d\n", $? >> 8;
}
=cut
#print $sipp_test "\n";
#printf "$? \n";
#printf "command exited with value %d\n", $? >> 8;
