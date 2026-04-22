package main

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func capture(stop <-chan struct{}, iface string, snapLen int32, conn *net.UDPConn, st *stats) {
	handle, err := pcap.OpenLive(iface, snapLen, true, pcap.BlockForever) // promiscuous=true
	if err != nil {
		log.Printf("[%s] pcap open: %v", iface, err)
		return
	}

	// Closing handle unblocks the packet source when stop fires
	go func() {
		<-stop
		handle.Close()
	}()

	if err := handle.SetBPFFilter("udp and (port 67 or port 68)"); err != nil {
		log.Printf("[%s] bpf filter: %v", iface, err)
		handle.Close()
		return
	}

	log.Printf("[%s] promiscuous capture started", iface)

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.NoCopy = true
	for pkt := range src.Packets() {
		processDHCP(pkt, iface, conn, st)
	}

	log.Printf("[%s] capture stopped", iface)
}

func processDHCP(pkt gopacket.Packet, iface string, conn *net.UDPConn, st *stats) {
	// Extract VLAN ID from 802.1Q tag, if present
	var vlanID uint16
	if v := pkt.Layer(layers.LayerTypeDot1Q); v != nil {
		vlanID = v.(*layers.Dot1Q).VLANIdentifier
	}

	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	payload := udpLayer.(*layers.UDP).Payload
	if len(payload) < 240 {
		return
	}

	// Only BOOTREQUEST (op=1, client → server)
	if payload[0] != 1 {
		return
	}

	// Verify DHCP magic cookie at offset 236: 99.130.83.99
	if payload[236] != 99 || payload[237] != 130 || payload[238] != 83 || payload[239] != 99 {
		return
	}

	// Only forward DISCOVER (1) and REQUEST (3)
	mt := dhcpMsgType(payload[240:])
	if mt != 1 && mt != 3 {
		return
	}

	// Forward raw DHCP bytes to profiler
	if _, err := conn.Write(payload); err != nil {
		st.incrError(iface)
		return
	}
	st.incrForwarded(iface, vlanID)
}

// dhcpMsgType parses DHCP options to find option 53 (Message Type).
func dhcpMsgType(opts []byte) byte {
	for i := 0; i < len(opts)-2; {
		if opts[i] == 255 { // end option
			break
		}
		if opts[i] == 0 { // padding
			i++
			continue
		}
		l := int(opts[i+1])
		if i+2+l > len(opts) {
			break
		}
		if opts[i] == 53 && l == 1 {
			return opts[i+2]
		}
		i += 2 + l
	}
	return 0
}
