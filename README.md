# go-tcpdump

## Overview
Tcpdump implemented in Go. Has the ability to monitor network packets and save to an output file. You can also provide a BPF filter on the packets.

```bash
Usage of ./go-tcp.bin:
  -f string
    	Set a BPF packet filer (ex. 'udp and dst port 5355')
  -i string
    	Network interface to listen on (name or ID)
  -l	List network interfaces
  -n int
    	Number of packets to capture (Default: continue until stopped)
  -w string
    	File to save the data to
You must specify an interaface to use
```

## Requirements
The program relies on the following modules:
- github.com/google/gopacket
- github.com/google/gopacket/layers
- github.com/google/gopacket/pcap
- github.com/google/gopacket/pcapgo

## Setup
Make sure go is installed and then run the following:
```bash
git clone https://github.com/lum8rjack/go-tcpdump
cd go-tcpdump
make
```

## Examples

Listing the network interfaces
```bash
sudo ./go-tcp.bin -l
ID: 1
Name: eth0
MAC: aa:bb:cc:dd:ee:12
Devices addresses: 
	IP address: 192.168.100.20
	Subnet mask: 255.255.255.0

ID: 2
Name: lo
MAC: 
Devices addresses: 
	IP address: 127.0.0.1
	Subnet mask: 255.0.0.0
```

Capturing only 100 packets and saving to a file.
```bash
sudo ./go-tcp.bin -i 1 -n 100 -w test.pcap
2022/09/27 22:43:52 Started go-tcpdump
2022/09/27 22:43:52 Listening on  eth0, capture size 65535
2022/09/27 22:43:55 ARP aa:bb:cc:dd:ee:12 --> ff:ff:ff:ff:ff:ff (len:60)
2022/09/27 22:44:02 UDP 192.168.100.20:35191 --> 192.168.100.42.4:443(https) (len:1292)
2022/09/27 22:44:02 UDP 192.168.100.20:35191 --> 192.168.100.42.4:443(https) (len:116)
2022/09/27 22:44:02 UDP 192.168.100.42.4:443(https) --> 192.168.100.20:35191 (len:1292)
2022/09/27 22:44:02 UDP 192.168.100.42.4:443(https) --> 192.168.100.20:35191 (len:830)
2022/09/27 22:44:02 UDP 192.168.100.42.4:443(https) --> 192.168.100.20:35191 (len:111)
2022/09/27 22:44:02 UDP 192.168.100.20:35191 --> 192.168.100.42.4:443(https) (len:120)
2022/09/27 22:44:02 UDP 192.168.100.20:35191 --> 192.168.100.42.4:443(https) (len:75)
2022/09/27 22:44:02 UDP 192.168.100.42.4:443(https) --> 192.168.100.20:35191 (len:67)
2022/09/27 22:44:02 UDP 192.168.100.20:35191 --> 192.168.100.42.4:443(https) (len:75)
2022/09/27 22:44:02 UDP 192.168.100.42.4:443(https) --> 192.168.100.20:35191 (len:162)
2022/09/27 22:44:02 UDP 192.168.100.20:35191 --> 192.168.100.42.4:443(https) (len:75)
2022/09/27 22:44:03 UDP 192.168.1.83:57621 --> 192.168.1.255:57621 (len:86)
...
```

