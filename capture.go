package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	SNAPSHOTLENGTH int32         = 65535            // Snapshot length
	PROMISCUOUS    bool          = false            // Promiscuous mode
	TIMEOUT        time.Duration = -1 * time.Second // Timeout
)

var (
	numpackets       int    = 0
	outputfile       string = ""
	packetstocapture int    = 0
	packetfilter     string = ""
)

type Devices struct {
	devices []Device
}

type Device struct {
	ID          int
	Name        string
	Description string
	MAC         net.HardwareAddr
	Addresses   []Addrs
}

type Addrs struct {
	IP      net.IP
	Netmask net.IPMask
}

// Set the BPF filter
func SetPacketFilter(f string) {
	packetfilter = f
}

// Set thefilename to save the data to
func SetSaveFile(f string) {
	outputfile = f
}

// Set the number of packets you want to capture
func SetPacketsToCapture(n int) {
	packetstocapture = n
}

// Get the mac address of the provided device
func GetMac(device string) net.HardwareAddr {
	var hw net.HardwareAddr = nil

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal("error with interfaces")
	}

	for _, iface := range ifaces {
		if iface.Name == device {
			return iface.HardwareAddr
		}
	}
	return hw
}

// Get a list of all network interfaces
func GetAllDevices() (Devices, error) {
	// Setup Devices struct
	devicesStruct := Devices{}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return devicesStruct, errors.New("error getting all devices")
	}

	// Loop through each device
	id := 1
	for _, device := range devices {
		// Create new Device
		d := Device{}
		d.ID = id
		d.Name = device.Name
		mac := GetMac(device.Name)
		d.MAC = mac

		for _, address := range device.Addresses {
			a := Addrs{IP: address.IP, Netmask: address.Netmask}
			d.Addresses = append(d.Addresses, a)
		}

		// Add to list
		devicesStruct.devices = append(devicesStruct.devices, d)
		id++
	}

	return devicesStruct, nil
}

// Print all devices and their details
func (d *Devices) PrintAllDevices() error {
	for _, dev := range d.devices {
		// Do not print if there are no addressses
		if len(dev.Addresses) != 0 {
			fmt.Printf("ID: %d\n", dev.ID)
			fmt.Printf("Name: %s\n", dev.Name)
			fmt.Printf("MAC: %s\n", dev.MAC.String())
			fmt.Println("Devices addresses: ")
			for _, address := range dev.Addresses {
				fmt.Printf("\tIP address: %s\n", address.IP.String())
				addr := net.IP(address.Netmask).String()
				fmt.Printf("\tSubnet mask: %s\n", addr)
			}
			fmt.Println()
		}
	}

	return nil
}

func (d *Devices) GetDevice(s string) (Device, error) {
	retDev := Device{}

	for _, dev := range d.devices {
		if dev.Name == s || strconv.Itoa(dev.ID) == s {
			return dev, nil
		}
	}

	return retDev, errors.New("error finding device")
}

func printPacket(p gopacket.Packet) {
	// Variables we want to print
	var src_ip string
	var src_port string
	var des_ip string
	var des_port string
	var proto string
	sendtime := p.Metadata().Timestamp.Format("2006/01/02 15:04:05")
	packetlength := p.Metadata().Length

	// Check if it is IPv6
	ip6Layer := p.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil {
		ip, _ := ip6Layer.(*layers.IPv6)
		src_ip = ip.SrcIP.String()
		des_ip = ip.DstIP.String()
	}

	// Check if it is IPv4
	ipLayer := p.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		src_ip = ip.SrcIP.String()
		des_ip = ip.DstIP.String()
	}

	// If src_ip is blank then it was an ethernet packet (layer 2) probably
	if src_ip == "" {
		// Get Ethernet layer
		ethLayer := p.Layer(layers.LayerTypeEthernet)
		if ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			src_ip = eth.SrcMAC.String()
			des_ip = eth.DstMAC.String()
			proto = "ETH"
		}
	}

	// Check if it is UDP
	udpLayer := p.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		src_port = udp.SrcPort.String()
		des_port = udp.DstPort.String()
		proto = "UDP"
	}

	// Check if it is TCP
	tcpLayer := p.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		src_port = tcp.SrcPort.String()
		des_port = tcp.DstPort.String()
		proto = "TCP"
	}

	// Check if it is ARP
	arpLayer := p.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		proto = "ARP"
	}

	// Check if it is PING
	ping4Layer := p.Layer(layers.LayerTypeICMPv4)
	if ping4Layer != nil {
		proto = "ICMP"
	}
	ping6Layer := p.Layer(layers.LayerTypeICMPv4)
	if ping6Layer != nil {
		proto = "ICMP"
	}

	// Print out the details if there is a port associated
	var o string
	if src_port != "" {
		o = fmt.Sprintf("%s %s %s:%s --> %s:%s (len:%d)", sendtime, proto, src_ip, src_port, des_ip, des_port, packetlength)
	} else {
		o = fmt.Sprintf("%s %s %s --> %s (len:%d)", sendtime, proto, src_ip, des_ip, packetlength)
	}

	fmt.Println(o)
}

// Start capturing packets
func (d *Device) Start() {
	// If user wants to save the data to a file
	var w *pcapgo.Writer
	if outputfile != "" {
		// Open output pcap file and write header
		f, _ := os.Create(outputfile)
		w = pcapgo.NewWriter(f)
		w.WriteFileHeader(uint32(SNAPSHOTLENGTH), layers.LinkTypeEthernet)
		defer f.Close()
	}

	// Open the device for capturing
	handler, err := pcap.OpenLive(d.Name, SNAPSHOTLENGTH, PROMISCUOUS, TIMEOUT)
	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()

	// Set filter if one was provided
	if packetfilter != "" {
		err := handler.SetBPFFilter(packetfilter)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Start processing packets
	source := gopacket.NewPacketSource(handler, handler.LinkType())

	for packet := range source.Packets() {
		// Increase the number of packets we have processed
		numpackets++

		// Print details of the packet
		printPacket(packet)

		// Check if we should write the packe to disk
		if outputfile != "" {
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}

		// Break if we captured all the packets we wanted
		if packetstocapture != 0 && numpackets >= packetstocapture {
			log.Printf("Done capturing %d packets\n", packetstocapture)
			break
		}
	}

}
