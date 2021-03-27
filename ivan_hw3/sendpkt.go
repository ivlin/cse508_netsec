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
    ip := &layers.IPv4{
		SrcIP:    net.IPv4(192, 168, 1, 246),
		DstIP:    net.IPv4(192, 168, 1, 246),
		Protocol: layers.IPProtocolTCP,
	}
	//  TCP header
	tcp := &layers.TCP{
		SrcPort: 53,
		DstPort: 53,
		Seq:     1105024978,
		SYN:     true,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)

    buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		log.Fatal(err)
	}

	handle, err := pcap.OpenLive(
		"enp0s3",	// device
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