#!/usr/bin/perl -w
use strict;
use warnings;
use lib "/omd/versions/1.2.3i1.dmmk/lib/nagios/plugins";
use utils qw($TIMEOUT %ERRORS &print_revision &support);
use Getopt::Long;
use Time::HiRes qw(time);
use Time::Format qw(%time);
use File::Find ();
use POSIX qw(setuid);
#use Test::More;

#---[Define Variables]
my $to_num = '15555555555';
my $sipp_path; 
my $call_duration = '8000';
my $sip_proxy_ip = 'sip.myprovider.com';
my $pcap_path = '/var/spool/pcapsipdump/';
my $output_path = '/var/spool/pcapsipdump/output/';
my $uac_path = '/opt/omd/sites/monitor_demo/version/lib/nagios/plugins/sipp/';
my $pcap_file;
my $pcap_time;
my $start_time;
my $payload;
my $wav_file;
my $raw_file;
my $qos;
my @qos_stats;
my $pcap2payload;
my $raw2wav;
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
$start_time = time;
$start_time += 1; # pcap timestamp is always 1 second behind script launch time
$pcap_time = $time{'yyyymmddhhmmss', $start_time};
substr($pcap_time, 8, 0) = '-';


#---[Run SIPp]
$command = "sipp -sf " . $uac_path . "uac.xml -inf " . $uac_path . "user.csv " . $sip_proxy_ip . " -r 1 -mi 10.128.7.112 -m 1 -s " . $to_num . " -d ". $call_duration;
$sipp_path = `$command`;


#---[Find the pcap file and save result to $pcap_file]
$command = "/usr/bin/find " . $pcap_path . " -type f -name '" . $pcap_time . "*" . $to_num . "*pcap'";
chomp($pcap_file = `$command`);
if ($pcap_file) {
} else {
	print "pcap file not found\n";
        exit $ERRORS{'CRITICAL'};
}
=head
File::Find::find({wanted => \&wanted}, $pcap_path);

sub wanted {
        #print "$File::Find::name/$_\n";
#    if ( $_ =~ /^$pcap_time.*.$to_num.*pcap\z/s ) {
    if ( $_ =~ /$to_num.*pcap\z/s ) {
#        print "function: $File::Find::name\n";
        $pcap_file = $File::Find::name;
    }
}
=cut


#---[Analyze the call quality with tshark]
$command = "/usr/bin/tshark -n -r " . $pcap_file . " -q -z rtp,streams | /usr/bin/awk 'FNR == 3 {print}'";
$qos = `$command`;
if ($qos) {
	$qos =~ s/(\(|\%\))//g;
	@qos_stats = split(/ +/, $qos);
} else {
	print "RTP not being analyzed\n";
	exit $ERRORS{'CRITICAL'};
}


#---[Convert pcap file into rtp payload]
$payload = $pcap_time . "-" . $to_num . ".payload";
$command = "/usr/bin/tshark -n -r " . $pcap_file . " -R rtp -T fields -e rtp.payload | /usr/bin/tee " . $output_path . $payload;
$pcap2payload = `$command`;


#---[Convert payload to wav file]
rtp2wav();


#---[Final Output to Nagios]
if ($qos_stats[11] < 15 || $qos_stats[13] < 5) {
        print "Call to " . $to_num . " was successful|loss=" . $qos_stats[11] . "%;20;30;; jitter=" . $qos_stats[13] . "ms;10;20;;\n";
        exit $ERRORS{'OK'};
} elsif ($qos_stats[11] < 20 || $qos_stats[13] < 10) {
	print "Packet Loss is " . $qos_stats[11] . " Average Jitter is " . $qos_stats[13] . "|loss=" . $qos_stats[11] . "%;20;30;; jitter=" . $qos_stats[13] . "ms;10;20;;\n";
	exit $ERRORS{'WARNING'};
} else {
        print "Packet Loss is " . $qos_stats[11] . " Average Jitter is " . $qos_stats[13] . "|loss=" . $qos_stats[11] . "%;20;30;; jitter=" . $qos_stats[13] . "ms;10;20;;\n";
	exit $ERRORS{'CRITICAL'};
}


#---[translate the ascii-hex payload from tshark to actual binary data]
sub rtp2wav{
	$raw_file = $pcap_time . "-" . $to_num . ".raw";
        open(MYFILE, "<", $output_path . $payload)
                or die "cannot open < $payload: $!";
        open(OUTFILE, ">", $output_path . $raw_file);
        while(<MYFILE>) {
                my $line = $_;
                chop $line;
		my $char;
                foreach $char(split(/:/,$line)) {
                        print OUTFILE chr(hex($char));
                }
        }
        close(MYFILE);
        close(OUTFILE);
	$wav_file = $pcap_time . "-" . $to_num . ".wav";
	$command = "sox -t raw -r 8000 -c 1 -U " . $output_path . $raw_file . " " . $output_path . $wav_file;
	$raw2wav = `$command`;
}

