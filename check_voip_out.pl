#!/usr/bin/perl
use strict;
use warnings;
use lib "/omd/versions/1.2.3i1.dmmk/lib/nagios/plugins";
use utils qw($TIMEOUT %ERRORS &print_revision &support);
use Getopt::Long;
use Time::HiRes qw(time);
use Time::Format qw(%time);
use Test::More;

#---[Define Variables]
my $to_num = '18582240094';
my $call_duration = '10000';
my $sip_proxy_ip = 'sip.phone.com';
my $pcap_path = '/var/spool/pcapsipdump/';
my $pcap_file;
my $pcap_time;
my $start_time;
my $payload = 'testfile.payload';
my $wav_file = 'testfile.wav';
my $raw_file = 'testfile.raw';
my $qos;
my $pcap2payload;
my $command;

#---[Nagios output variables]
my $perf_sipp;
my $perf_qos;
my $perf_stt;

#---[Usage]
=head
Getopt::Long::Configure('bundling', 'no_ignore_case');
    GetOptions
    ("V|v"    => \&version,
     "h|help"       => \&help,
     "w|warning=s"  => \$opt_w,
     "c|critical=s" => \$opt_c,
     "P|port=s" => \$opt_p,
     "U|url=s" => \$opt_U,);
=cut

#---[Get time and use it later to search pcap file]
$pcap_time = $time{'yyyymmddhhmmss'};
substr($pcap_time, 8, 0) = '-';
print "$pcap_time \n";

#---[Run SIPp]
system("sipp -sf ../sipp/uac.xml -inf ../sipp/user.csv $sip_proxy_ip -r 1 -mi 10.128.7.112 -m 1 -s $to_num -d $call_duration") >> 8;

if ($? == -1) {
	print "SIPp failed to execute: $!\n";
	exit $ERRORS{'CRITICAL'};
} elsif ($? & 127) {
	printf "child died - signal %d, %s coredump\n",
		($? & 127), ($? & 128) ? 'with' : 'without';
	exit $ERRORS{'CRITICAL'};
} elsif ($? >> 8 == 0) {
} else {
	printf "child exited with value %d\n", $? >> 8;
	exit $ERRORS{'CRITICAL'};
}

#---[Find the pcap file and save result to $pcap_file]
$command = "find " . $pcap_path . " -type f -name '*" . $to_num . "*pcap' -mmin -" . $call_duration / 50000;
#print "$command\n";
chomp($pcap_file = `$command`);

if (defined $pcap_file) {
} else {
	print "pcap file not found\n";
        exit $ERRORS{'CRITICAL'};
}
#print "$pcap_file\n";

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

#---[Analyze the call quality with tshark]
#print "Analyze the call quality with tshark \n";
$command = "tshark -n -r " . $pcap_file . " -q -z rtp,streams";
print "$command\n";
$qos = `$command`;
if (defined $qos) {
} else {
	print "RTP not being analyzed\n";
	exit $ERRORS{'CRITICAL'};
}

#---[Convert pcap file into rtp payload]
#print "Convert pcap file into rtp payload \n";
$command = "tshark -n -r " . $pcap_file . " -R rtp -T fields -e rtp.payload | tee " . $payload;
$pcap2payload = `$command`;

#---[Convert payload to wav file]
rtp2wav();

#---[Final Output to Nagios] 

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

