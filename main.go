package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	// Setup flags
	intface := flag.String("i", "", "Network interface to listen on (name or ID)")
	filter := flag.String("f", "", "Set a BPF packet filer (ex. 'udp and dst port 5355')")
	list := flag.Bool("l", false, "List network interfaces")
	outfile := flag.String("w", "", "File to save the data to")
	num := flag.Int("n", 0, "Number of packets to capture (Default: continue until stopped)")
	flag.Parse()

	// Get the list of devices
	d, err := GetAllDevices()
	if err != nil {
		fmt.Println("Error getting the network interfaces")
		os.Exit(1)
	}

	if *list {
		d.PrintAllDevices()
		os.Exit(0)
	}

	// Check if we specified an interface
	if *intface == "" {
		flag.Usage()
		fmt.Println("You must specify an interaface to use")
		os.Exit(0)
	}

	dev, err := d.GetDevice(*intface)
	if err != nil {
		fmt.Println("Invalid interface specified")
		os.Exit(0)
	}

	if *outfile != "" {
		SetSaveFile(*outfile)
	}

	if *num != 0 {
		SetPacketsToCapture(*num)
	}

	if *filter != "" {
		SetPacketFilter(*filter)
	}

	log.Printf("Started go-tcpdump")
	log.Printf("Listening on  %s, capture size %d\n", dev.Name, SNAPSHOTLENGTH)
	dev.Start()
}
