package main

import (
	"fmt"
	"flag"
	"net"
	"strings"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func handlePacket(packet gopacket.Packet) {
	fmt.Println("")
	dt := packet.Metadata().CaptureInfo.Timestamp
	fmt.Printf("%04d-%02d-%02d %02d:%02d:%02d.%d\n", dt.Year(), dt.Month(), dt.Day(), dt.Hour(), dt.Minute(), dt.Second(), dt.Nanosecond())
	for _, layer := range packet.Layers() {
		fmt.Println(gopacket.LayerDump(layer))
	}
}

/*
 * Code referenced from gopacket pcap documentation
 */
func liveCapture(iface_name string, keyString string, bpf string) {
	if handle, err := pcap.OpenLive(iface_name, 1024, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(bpf); err != nil {  // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if keyString == "" || strings.Contains(packet.String(), keyString) {
				handlePacket(packet)
			}
		}
	}
}

func offlineCapture(fname string, keyString string, bpf string) {
	fmt.Printf("Capturing on from file %s\n", fname)
	if handle, err := pcap.OpenOffline(fname); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(bpf); err != nil {  // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if keyString == "" || strings.Contains(packet.String(), keyString) {
				handlePacket(packet)
			}
		}
	}
}

func main() {
	interfacePtr := flag.String("i", "", "Live capture from the network device <interface>.")
	pcapPtr := flag.String("r", "", "Read packets from <file> in tcpdump format.")
	keyStringPtr := flag.String("s", "", "Keep only packets that contain <string> in their payload (after any BPF filter is applied).")

	flag.Parse()

	_ = pcapPtr
	filter := strings.Join(flag.Args(), " ")

	interfaceList, _ := net.Interfaces()
	if *pcapPtr != "" {
		offlineCapture(*pcapPtr, *keyStringPtr, filter)
	}
	for _, iface := range interfaceList {
		if *interfacePtr == "" || iface.Name == *interfacePtr {
			liveCapture(iface.Name, *keyStringPtr, filter)
		}
	}
}
