# check_voip_call

### Purpose
Monitor VoIP call quality
### Prerequisites
Here are some tools you need to install on your server before check_voip_call scripts will work for you.

- SIPp
- tshark
- pcapsipdump
- sox
- Perl with CPAN

#### SIPp
```
sipp -sf uac.xml -inf user.csv -i 10.128.7.103 10.128.7.103 -r 40 -m 5000 -s 5000 -d 60000
sipp -sf uac.xml -inf user.csv 10.128.7.103 -r 1 -m 1 -s 15555555555 -d 60000
sipp -sf uac.xml -inf user.csv sip.sip-server.com -r 1 -mi 10.128.7.103 -m 3 -s 15555555555 -d 15000
```

#### tshark
```
tshark -n -r test.pcap -R rtp -R "rtp.ssrc == 0x855bd195" -T fields -e rtp.payload | tee payloads
tshark -n -r test.pcap -R rtp -T fields -e rtp.payload | tee payloads
tshark -n -r /var/spool/pcapsipdump/20130809/15/20130809-154947-74918-18582240094-1-6778\@127.0.1.1.pcap -q -z rtp,streams
```

#### pcapsipdump
#### sox
```
sox -t raw -r 8000 -c 1 -U sip_1call.raw  sip_call.wav
```

### Installation

### System Configuration

### Alternative Audio Capturing Tools
- Oreka - https://sourceforge.net/projects/oreka/?source=recommended
- VoIP monitor - 
- ECG Extract Call - http://www.e-c-group.com/software/ecg_extract_call/
- UCSniff - http://www.viperlab.net/tools/ucsniff
- xplico - http://www.xplico.org/
- pcapsipdump - http://apt.opensips.org/pool/main/p/pcapsipdump/

**Audio Conversion Tools**
- pjsip: 
    http://serverfault.com/questions/122024/checking-rtp-stream-audio-quality
    http://www.pjsip.org/download.htm
    Note: pcaputil needs the pcap in lipcap format with RTP only. So you need to convert the pcap with tshark fisrt.

### Caveat

### Credit
http://mawhin.blogspot.com/2008/02/roll-your-own-voip-analysis-its-not.html
