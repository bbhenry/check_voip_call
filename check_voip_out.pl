#!/usr/bin/perl
use strict;
use warnings;
use Time::HiRes qw(time);
use Time::Format qw(%time);
use Test::More;
use File::Find ();

## Define Variables
my $to_num = '18582240094';
my $call_duration;
my $pcap_path = '/var/spool/pcapsipdump/';
my $pcap_file;
my $pcap_time;
my $start_time;
my $destination_num;
my $payload = 'testfile.payload';
my $wav_file = 'testfile.wav';
my $raw_file = 'testfile.raw';
my $qos;
my $pcap2payload;
my $command;

#my $raw2wave;

## Get time and use it later to search pcap file
$pcap_time = $time{'yyyymmddhhmmss'};
substr($pcap_time, 8, 0) = '-';
print "$pcap_time \n";

## Run SIPp
ok(system("sipp -sf ../sipp/uac.xml -inf ../sipp/user.csv sip.phone.com -r 1 -mi 10.128.7.112 -m 1 -s $to_num -d 15000") >> 8 eq 0, "SIPp call made");

## Find the pcap file and save result to $pcap_file
print "Find the pcap file and save result to \$pcap_file \n";
$command = "find " . $pcap_path . " -type f -name '*" . $to_num . "*pcap' -mmin -0.3";
print "$command\n";
chomp($pcap_file = `$command`);
print "$pcap_file\n";
=head
File::Find::find({wanted => \&wanted}, $pcap_path);

sub wanted {
        #print "$File::Find::name/$_\n";
    if ( $_ =~ /^$pcap_time.*pcap\z/s ) {
        print "function: $File::Find::name\n";
        $pcap_file = $File::Find::name;
    }
}
=cut

## Analyze the call quality with tshark
print "Analyze the call quality with tshark \n";
$command = "tshark -n -r " . $pcap_file . " -q -z rtp,streams";
print "$command\n";
$qos = `$command`;
print "$qos \n";

## Convert pcap file into rtp payload
print "Convert pcap file into rtp payload \n";
$command = "tshark -n -r " . $pcap_file . " -R rtp -T fields -e rtp.payload | tee " . $payload;
$pcap2payload = `$command`;

## Convert payload to wav file
rtp2wav();


## translate the ascii-hex payload from tshark to actual binary data
sub rtp2wav{
        open(MYFILE, "<", $payload)
                or die "cannot open < $payload: $!";
        open(OUTFILE, ">", $raw_file);
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
	$raw2wav = `sox -t raw -r 8000 -c 1 -U $raw_file $wav_file`;
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
