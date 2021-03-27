package main

import (
	"log"
	"fmt"
	"net"
	"time"
    "github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
)

func main() {
    eth := &layers.Ethernet{
        SrcMAC: net.HardwareAddr{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbf},
        DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	EthernetType: layers.EthernetTypeIPv4,
    }
    ip := &layers.IPv4{
	Version:  uint8(4),
	SrcIP:    net.IPv4(192, 168, 1, 246),
	DstIP:    net.IPv4(192, 168, 1, 246),
	Protocol: layers.IPProtocolTCP,
    }
    // TCP header
    tcp := &layers.TCP{
	SrcPort: 53,
	DstPort: 53,
	Seq:     11,
	SYN:     true,
	Window:  14600,
    }
    tcp.SetNetworkLayerForChecksum(ip)

    buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
    }
    if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte{1,2,3,4})); err != nil {
        log.Fatal(err)
    }

    handle, err := pcap.OpenLive(
		"eth0",	// device
		10240,
		false,
		1000000 * time.Nanosecond,
    )
    if err != nil {
        fmt.Println("Open handle error", err.Error())
    }
    defer handle.Close()

    //send
    if err := handle.WritePacketData(buf.Bytes()); err != nil {
        fmt.Println("Send error", err.Error())
    } else {
        fmt.Println("Sent")
    }
}
