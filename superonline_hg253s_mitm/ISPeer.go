package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	//"golang.org/x/net/proxy"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	forwarded = 0
	blocked   = 0
	caught    = 0

	PPPoESession = uint16(0)
)

type BridgePort struct {
	iface  *net.Interface
	handle *pcap.Handle
	source net.HardwareAddr
}

const (
	INITIALIZED = iota
	ESTABLISHED = iota
	WAITING     = iota
	TERMINATING = iota
	TERMINATED  = iota
	COMPLETED   = iota
)

const (
	OUTGOING = iota
	INCOMING = iota
)

// TODO: add lastactivetime/timeout
type Connection struct {
	srcPort        uint16
	dstPort        uint16
	srcIP          net.IP
	dstIP          net.IP
	state          int
	seq            uint32
	ack            uint32
	window         uint16
	responseBuffer []byte
	outgoingPort   BridgePort
	incomingPort   BridgePort
}

type ACSHeader struct {
	Cookie        string
	SOAPAction    string
	ContentLength uint64
}

func generateIncomingPacket(connection Connection, SYN bool, ACK bool, FIN bool, RST bool, payload []byte) (packet []byte, err error) {
	eth := layers.Ethernet{
		SrcMAC:       connection.incomingPort.source,
		DstMAC:       connection.outgoingPort.source,
		EthernetType: layers.EthernetTypePPPoESession,
	}

	pppoe := layers.PPPoE{
		Version:   1,
		Type:      1,
		Code:      layers.PPPoECodeSession,
		SessionId: PPPoESession,
	}

	ppp := layers.PPP{
		PPPType: layers.PPPTypeIPv4,
	}

	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    connection.dstIP,
		DstIP:    connection.srcIP,
		Protocol: layers.IPProtocolTCP,
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(connection.dstPort),
		DstPort: layers.TCPPort(connection.srcPort),
		Window:  connection.window,
		Seq:     connection.seq,
	}

	if ACK {
		tcp.ACK = true
		tcp.Ack = connection.ack
	}

	if FIN {
		tcp.FIN = true

		if payload != nil && len(payload) != 0 {
			fmt.Printf("[-] WARNING: TCP payload is not accepted in FIN packet. Ignoring payload...\n")
		}
		payload = nil
	} else if RST {
		tcp.RST = true
		tcp.ACK = false
		tcp.Ack = 0

		if payload != nil && len(payload) != 0 {
			fmt.Printf("[-] WARNING: TCP payload is not accepted in RST packet. Ignoring payload...\n")
		}
		payload = nil
	} else if SYN {
		tcp.SYN = true

		if payload != nil && len(payload) != 0 {
			fmt.Printf("[-] WARNING: TCP payload is not accepted in SYN packet. Ignoring payload...\n")
		}
		payload = nil
	}

	tcp.SetNetworkLayerForChecksum(&ip)

	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, options,
		&eth,
		&pppoe,
		&ppp,
		&ip,
		&tcp,
		gopacket.Payload(payload))

	if err != nil {
		return
	}

	packet = buffer.Bytes()
	return
}

func generatePacket(label int, eth *layers.Ethernet, pppoe *layers.PPPoE, ip *layers.IPv4, tcp *layers.TCP, payload []byte) (packet []byte, err error) {
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
		return
	}

	packet = buffer.Bytes()
	return
}

func getHeaderValue(payload []byte) string {
	var (
		sidx = 0
		lidx = 0

		valueSide = false
		sidxSet   = false
	)
	for lidx, b := range payload {
		if b == '\n' || b == '\r' {
			break
		}

		if !valueSide && b == ':' {
			valueSide = true
			continue
		} else if valueSide && !sidxSet {
			if b == ' ' {
				continue
			}

			sidx = lidx
			sidxSet = true
		}

	}

	return string(payload[sidx:lidx])
}

func extractHeaders(payload []byte) (header ACSHeader) {

	c := 0
	for i, b := range payload {
		if b != '\n' {
			continue
		}

		if len(payload) >= i+1 {
			break
		}

		if payload[i+1] == 'C' {
			if bytes.Equal(payload[i+2:i+7], []byte("ookie")) {
				header.Cookie = getHeaderValue(payload[i+1:])
				c++

				if c == 3 {
					break
				}
			} else if bytes.Equal(payload[i+2:i+15], []byte("ontent-Length")) {
				cl, _ := strconv.ParseInt(getHeaderValue(payload[i+1:]), 10, 64)
				header.ContentLength = uint64(cl)

				c++

				if c == 3 {
					break
				}
			}

		} else if payload[i+1] == 'S' {
			if !bytes.Equal(payload[i+2:i+11], []byte("OAPACtion")) {
				continue
			}

			header.SOAPAction = getHeaderValue(payload[i+1:])
			c++

			if c == 3 {
				break
			}
		}

	}

	return
}

func extractRequestPath(payload []byte) (path string) {
	path = "/"

	idx := 5
	for i, b := range payload[5:] {
		if b == ' ' {
			idx = i
			break
		}
	}

	path = string(payload[5:idx])
	return
}

func extractBody(payload []byte, length uint64) (body string) {
	body = ""
	for i, b := range payload {
		if b == '\r' {
			if !bytes.Equal(payload[i+1:i+4], []byte("\n\r\n")) {
				continue
			}

			if len(payload) < i+4+int(length) {
				return
			}

			body = string(payload[i+4 : i+4+int(length)])
			return
		}
	}

	return
}

func generateHTTPResponse(resp *http.Response) (data []byte, err error) {
	data = []byte(resp.Proto)

	data = append(data, []byte{' '}...)
	data = append(data, []byte(resp.Status)...)
	data = append(data, []byte{'\r', '\n'}...)

	data = append(data, []byte("Date: ")...)
	data = append(data, []byte(resp.Header.Get("Date"))...)
	data = append(data, []byte{'\r', '\n'}...)

	data = append(data, []byte("Server: Apache\r\n")...)

	_, exists := resp.Header["Set-Cookie"]
	if exists {
		for _, cookie := range resp.Header["Set-Cookie"] {
			data = append(data, []byte("Set-Cookie: ")...)
			data = append(data, []byte(cookie)...)
			data = append(data, []byte{'\r', '\n'}...)
		}
	}

	data = append(data, []byte("Content-Length: ")...)
	data = append(data, []byte(strconv.Itoa(int(resp.ContentLength)))...)
	data = append(data, []byte{'\r', '\n'}...)

	data = append(data, []byte("Content-Type: text/xml; charset=UTF-8\r\n")...)

	data = append(data, []byte{'\r', '\n'}...)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	data = append(data, body...)

	return
}

// TODO: use bytes.Index instead of manual search
func processOutgoing(packet gopacket.Packet, wholePacket bool) (data []byte, err error) {

	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

	payload := tcp.Payload
	for i, b := range payload {
		if b != 'H' {
			continue
		}

		if i+13 >= len(payload) || bytes.Compare(payload[i+1:i+13], []byte("G253sC01B039")) != 0 {
			continue
		}

		fmt.Printf("[+] Modifying outgoing payload...\n")
		payload[i+11] = '3'
		payload[i+12] = '5'
		break
	}

	if !wholePacket {
		data = payload
		return
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

	err = gopacket.SerializeLayers(buffer, options,
		eth,
		vlan,
		pppoe,
		ppp,
		ip,
		tcp,
		gopacket.Payload(payload))

	if err != nil {
		return
	}

	data = buffer.Bytes()
	return
}

// TODO: use bytes.Index instead of manual search
func processIncoming(packet gopacket.Packet) (data []byte, err error) {
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	pppoe := packet.Layer(layers.LayerTypePPPoE).(*layers.PPPoE)
	ppp := packet.Layer(layers.LayerTypePPP).(*layers.PPP)
	ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

	var nPayload []byte
	payload := tcp.Payload
	for i, b := range payload {
		if b != 'h' {
			continue
		}

		if i+11 >= len(payload) || bytes.Compare(payload[i+1:i+11], []byte("ttps://acs")) != 0 {
			continue
		}

		fmt.Printf("[+] Modifying incoming payload...\n")
		nPayload = make([]byte, len(payload)+4)
		copy(nPayload, payload[:i])
		copy(nPayload[i:], []byte("http://acs.superonline.net:8016"))
		copy(nPayload[i+31:], payload[i+27:])
		break
	}
	if nPayload != nil {
		payload = nPayload
	}

	tcp.SetNetworkLayerForChecksum(ip)

	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buffer := gopacket.NewSerializeBuffer()

	err = gopacket.SerializeLayers(buffer, options,
		eth,
		pppoe,
		ppp,
		ip,
		tcp,
		gopacket.Payload(payload))

	if err != nil {
		return
	}

	data = buffer.Bytes()
	return
}

func isCompleteHTTPPayload(payload []byte) bool {
	idx := bytes.Index(payload, []byte("Content-Length"))

	if idx == -1 {
		return false
	}

	idx += len("Content-Length: ")

	lineEndIdx := 0
	for i, b := range payload[idx:] {
		if b != '\r' {
			continue
		}

		lineEndIdx = i
		break
	}

	if lineEndIdx == 0 {
		return false
	}

	cl, err := strconv.ParseUint(string(payload[idx:lineEndIdx]), 10, 64)
	if err != nil {
		fmt.Printf("THIS!: %s\n", err.Error())
		return false
	}

	body := extractBody(payload, cl)

	return body != ""
}

func forwardToHTTPS(payload []byte, responseCh chan []byte) {

	/*dial, err := proxy.SOCKS5("tcp4", "127.0.0.1:8080", nil, proxy.Direct)
	if err != nil {
		fmt.Printf("[-] Unable to set proxy: %s\n", err.Error())
	}

	tr := http.Transport{
		Dial: dial,
	}
	httpClient := http.Client{
		Transport: &tr,
	}*/
	httpClient := http.Client{}

	path := extractRequestPath(payload)

	header := extractHeaders(payload)

	body := extractBody(payload, header.ContentLength)

	req, err := http.NewRequest("POST", "https://acs.superonline.net"+path, bytes.NewBufferString(body))
	if err != nil {
		fmt.Printf("[-] Unable to create http request: %s\n", err.Error())
		return
	}

	req.Header.Set("User-Agent", "HW_ATP_HTTP")
	if header.Cookie != "" {
		req.Header.Set("Cookie", header.Cookie)
	}
	if header.SOAPAction != "" {
		req.Header.Set("SOAPAction", header.SOAPAction)
	}
	req.Header.Set("Content-type", "text/xml; charset=UTF-8")

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("[-] Error in HTTP request: %s\n", err.Error())
		return
	}
	defer resp.Body.Close()

	fmt.Printf("[+] Request forwarded to %s\n", path)

	resPayload, err := generateHTTPResponse(resp)
	if err != nil {
		fmt.Printf("[-] Error while generating HTTP response: %d\n", err.Error())
		return
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Printf("[-] Unexpected status code returned: %d\n", resp.StatusCode)
		fmt.Printf("%s", string(resPayload))
	}

	responseCh <- resPayload

	close(responseCh)
}

func handleTLSForward(bridgeCh chan *gopacket.Packet, outgoingPort BridgePort, incomingPort BridgePort) {

	outgoingChain := make(map[uint16]Connection)

	for {
		packet := <-bridgeCh

		tcp, _ := (*packet).Layer(layers.LayerTypeTCP).(*layers.TCP)
		ipLayer := (*packet).Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			fmt.Printf("[-] Probably caught an IPv6 connection, not supported at the moment\n")
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		connection, exists := outgoingChain[uint16(tcp.SrcPort)]

		if !exists {
			if !tcp.SYN {
				fmt.Printf("[-] The connection is not in its inital state but we don't know about it. Ignoring...\n")
				// TODO: send RST packet
				continue
			}

			connection = Connection{
				srcPort:        uint16(tcp.SrcPort),
				dstPort:        uint16(tcp.DstPort),
				srcIP:          ip.SrcIP,
				dstIP:          ip.DstIP,
				state:          INITIALIZED,
				seq:            tcp.Ack,
				ack:            tcp.Seq + 1,
				window:         tcp.Window,
				responseBuffer: make([]byte, 0),
				incomingPort:   incomingPort,
				outgoingPort:   outgoingPort,
			}

			fmt.Printf("[+] SYN received. Initialized connection with proxy. Sending SYNACK...\n")
			outgoingChain[connection.srcPort] = connection

			packet, err := generateIncomingPacket(connection, true, true, false, false, nil) // SYNACK
			if err != nil {
				fmt.Printf("[-] Error while generating packet: %s\n", err.Error())
				continue
			}
			err = outgoingPort.handle.WritePacketData(packet)
			if err != nil {
				fmt.Printf("[-] Error while sending SYNACK packet: %s\n", err.Error())
				continue
			}

			fmt.Printf("[+] SYNACK sent\n")

		} else if tcp.CWR || tcp.ECE || tcp.NS || tcp.URG {
			fmt.Printf("[-] Unsupported tcp flag received! Ignoring...\n")
			continue
		} else if tcp.RST {
			connection.state = COMPLETED

			outgoingChain[connection.srcPort] = connection

			fmt.Printf("[+] RST received. Connection is terminated\n")

		} else {

			if tcp.ACK && connection.state == INITIALIZED {
				connection.state = ESTABLISHED
				fmt.Printf("[+] Threeway handshake completed\n")
			} else if connection.state >= TERMINATED {
				if connection.state == TERMINATED {
					connection.state = COMPLETED
					outgoingChain[connection.srcPort] = connection
					continue
				}

				fmt.Printf("[-] Packet received for completed connection. Sending RST...\n")

				packet, err := generateIncomingPacket(connection, false, false, false, true, nil) // RST
				if err != nil {
					fmt.Printf("[-] Error while generating packet: %s\n", err.Error())
					continue
				}

				err = outgoingPort.handle.WritePacketData(packet)
				if err != nil {
					fmt.Printf("[-] Error while sending ACK packet: %s\n", err.Error())
					continue
				}

				fmt.Printf("[+] RST sent\n")
				continue
			}

			payload := tcp.Payload

			connection.seq = tcp.Ack
			connection.ack = tcp.Seq + uint32(len(payload))

			if len(payload) == 0 && !tcp.FIN {
				//fmt.Printf("[-] Zero payload tcp packet!\n%s\n", (*packet).Dump())
				outgoingChain[connection.srcPort] = connection
				continue
			}

			if tcp.FIN {
				connection.ack++

				fin := false
				if connection.state == ESTABLISHED {
					connection.state = TERMINATED
					fmt.Printf("[+] Received FIN from target. Connection is terminated, sending FINACK\n")

					fin = true
				} else if connection.state == TERMINATING {
					connection.state = COMPLETED
					tcp.FIN = false
					fmt.Printf("[+] Received FINACK from target. Connection is terminated, sending ACK\n")
				}

				packet, err := generateIncomingPacket(connection, false, true, fin, false, nil)
				if err != nil {
					fmt.Printf("[-] Error while generating packet: %s\n", err.Error())
					continue
				}

				err = outgoingPort.handle.WritePacketData(packet)
				if err != nil {
					fmt.Printf("[-] Error while sending packet: %s\n", err.Error())
					continue
				}

				outgoingChain[connection.srcPort] = connection
				fmt.Printf("[+] Sent\n")
				continue
			}

			var responseCh chan []byte
			if !tcp.FIN {
				mPayload, err := processOutgoing(*packet, false)
				if err != nil {
					fmt.Printf("[-] Unable to modify payload, continuing with unmodified packet: %s\n", err.Error())
					mPayload = payload
				}

				connection.responseBuffer = append(connection.responseBuffer, mPayload...)

				if isCompleteHTTPPayload(connection.responseBuffer) {
					responseCh = make(chan []byte)

					go forwardToHTTPS(connection.responseBuffer, responseCh)

					connection.state = WAITING
				}
			}

			packet, err := generateIncomingPacket(connection, false, true, false, false, nil)
			if err != nil {
				fmt.Printf("[-] Error while generating packet: %s\n", err.Error())
				continue
			}

			err = outgoingPort.handle.WritePacketData(packet)
			if err != nil {
				fmt.Printf("[-] Error while sending ACK packet: %s\n", err.Error())
				continue
			}

			outgoingChain[connection.srcPort] = connection
			fmt.Printf("[+] Sent\n")

			if connection.state != WAITING {
				continue
			}

			resPayload, ok := <-responseCh

			if !ok {
				fmt.Printf("[-] Couldn't receive http response: %s\n", err.Error())
				// TODO: terminate connection
				continue
			}

			data, err := generateIncomingPacket(connection, false, true, false, false, resPayload)
			if err != nil {
				fmt.Printf("[-] Error while generating packet from http response: %s\n", err.Error())
				continue
			}

			if len(data) <= outgoingPort.iface.MTU {
				err = outgoingPort.handle.WritePacketData(data)
				if err != nil {
					fmt.Printf("[-] Error while forwarding http response to %s: %s\n", outgoingPort.iface.Name, err.Error())
					// TODO: terminate connection
					continue
				}
			} else {
				fmt.Printf("[+] Fragmenting packet...\n")
				packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

				err = fragmentAndSend(OUTGOING, &packet, outgoingPort)
				if err != nil {
					fmt.Printf("[-] Error while fragmenting packet: %s\n", err.Error())
					return
				}
			}

			connection.seq += uint32(len(data))

			data, err = generateIncomingPacket(connection, false, true, true, false, nil)
			if err != nil {
				fmt.Printf("[-] Error while generating FINACK packet: %s\n", err.Error())
				continue
			}

			err = outgoingPort.handle.WritePacketData(data)
			if err != nil {
				fmt.Printf("[-] Error while sending FINACK to %s: %s\n", outgoingPort.iface.Name, err.Error())
				continue
			}

			connection.state = TERMINATING
			connection.seq++

			outgoingChain[connection.srcPort] = connection
		}
	}

}

func fragmentAndSend(label int, packet *gopacket.Packet, port BridgePort) (err error) {

	ethLayer := (*packet).Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		err = fmt.Errorf("Couldn't find ethernet layer, ignoring packet...\n")
		return
	}

	eth, _ := ethLayer.(*layers.Ethernet)

	pppoeLayer := (*packet).Layer(layers.LayerTypePPPoE)
	if pppoeLayer == nil {
		err = fmt.Errorf("Couldn't find PPPoE layer ignoring packet...\n")
		return
	}

	pppoe, _ := pppoeLayer.(*layers.PPPoE)

	ipLayer := (*packet).Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		err = fmt.Errorf("Couldn't find ipv4 layer(ipv6 isn't supported), ignoring packet...\n")
		return
	}

	ip, _ := ipLayer.(*layers.IPv4)

	tcpLayer := (*packet).Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		err = fmt.Errorf("Fragmentation is only supported for TCP. Ignoring...\n")
		return
	}

	tcp, _ := tcpLayer.(*layers.TCP)

	totalHeaderSize := len((*packet).Data()) - len(tcp.Payload)
	maxPayloadSize := port.iface.MTU - totalHeaderSize

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

		outgoingPacket, err := generatePacket(label, eth, pppoe, ip, tcp, payload[i*maxPayloadSize:i*maxPayloadSize+maxPayloadSize])
		if err != nil {
			err = fmt.Errorf("Error while generating fragmented packet for %s: %s\n", port.iface.Name, err.Error())
			return err
		}

		err = port.handle.WritePacketData(outgoingPacket)
		if err != nil {
			err = fmt.Errorf("Error while forwarding fragmented packet to %s: %s\n", port.iface.Name, err.Error())
			return err
		}
	}

	lastPayloadSize := len(payload) - i*maxPayloadSize

	tcp.Seq = seq

	outgoingPacket, err := generatePacket(label, eth, pppoe, ip, tcp, payload[i*maxPayloadSize:i*maxPayloadSize+lastPayloadSize])
	if err != nil {
		err = fmt.Errorf("Error while generating last fragmented packet for %s: %s\n", port.iface.Name, err.Error())
		return
	}

	err = port.handle.WritePacketData(outgoingPacket)
	if err != nil {
		err = fmt.Errorf("Error while forwarding last fragmented packet to %s: %s\n", port.iface.Name, err.Error())
		return
	}

	return
}

func bridge(outgoingPort BridgePort, incomingPort BridgePort, label int) {

	var ch chan *gopacket.Packet

	if label == OUTGOING {
		ch = make(chan *gopacket.Packet)
		go handleTLSForward(ch, outgoingPort, incomingPort)
	}

	for {
		data, inf, err := outgoingPort.handle.ReadPacketData()
		if err != nil {
			fmt.Printf("[-] Error while reading from %s handle: %s\n", label, err.Error())
			continue
		}

		if label == INCOMING { // strip out vss-monitoring trailer
			data = data[:len(data)-2]
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		pppoeLayer := packet.Layer(layers.LayerTypePPPoE)

		if pppoeLayer != nil {
			pppoe, _ := pppoeLayer.(*layers.PPPoE)

			PPPoESession = pppoe.SessionId
			//fmt.Printf("[+] Retreived PPPoE Session ID: %d\n", PPPoESession)
		}

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)

			if label == OUTGOING && bytes.Equal(ip.DstIP, []byte{85, 29, 13, 3}) {
				tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

				if tcp.DstPort == 8015 && len(tcp.Payload) > 0 {
					fmt.Printf("[+] Caught outgoing!\n")
					data, err = processOutgoing(packet, true)
					if err != nil {
						fmt.Printf("[-] Couldn't modify intercepted package: %s\n", err.Error())
						return
					}
				} else if tcp.DstPort == 8016 {
					ch <- &packet
				}

			} else if label == INCOMING && bytes.Equal(ip.SrcIP, []byte{85, 29, 13, 3}) {
				tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

				if tcp.SrcPort == 8015 && len(tcp.Payload) > 0 {
					fmt.Printf("[+] Caught incoming!\n")
					data, err = processIncoming(packet)
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
		packetSize := len(data)
		if packetSize <= incomingPort.iface.MTU {
			err = incomingPort.handle.WritePacketData(data)
			if err != nil {
				fmt.Printf("[-] Error while forwarding to %s: %s\n", incomingPort.iface.Name, err.Error())
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

		forwarded++
	}
}

func initHandle(iface *net.Interface, promisc bool) (handle *pcap.Handle, err error) {
	handle, err = pcap.OpenLive(iface.Name, 65535, promisc, pcap.BlockForever)

	return
}

func initPort(ifaceName string, mac net.HardwareAddr) (port BridgePort, err error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		err = fmt.Errorf("Error retrieving interface %s: %s", ifaceName, err.Error())
		return
	}

	promisc := ifaceName != "lo"
	handle, err := initHandle(iface, promisc)
	if err != nil {
		err = fmt.Errorf("Error while initializing handle: %s", err.Error())
		return
	}

	port = BridgePort{iface, handle, mac}
	return
}

func main() {

	ifaces := os.Args[1:]

	if len(ifaces) != 4 {
		fmt.Printf("[-] Missing arguments\n")
		return
	}

	fmt.Printf("[+] Configuring interfaces %s and %s...\n", ifaces[0], ifaces[2])

	inMac, err := net.ParseMAC(ifaces[1])
	if err != nil {
		fmt.Printf("[-] Invalid outgoing source MAC: %s\n", err.Error())
		return
	}

	outMac, err := net.ParseMAC(ifaces[3])
	if err != nil {
		fmt.Printf("[-] Invalid incoming source MAC: %s\n", err.Error())
		return
	}

	outgoingPort, err := initPort(ifaces[0], inMac)
	if err != nil {
		fmt.Printf("[-] Error while configuring input interface: %s\n", err.Error())
		return
	}
	defer outgoingPort.handle.Close()

	incomingPort, err := initPort(ifaces[2], outMac)
	if err != nil {
		fmt.Printf("[-] Error while configuring output interface: %s\n", err.Error())
		return
	}
	defer incomingPort.handle.Close()

	if outgoingPort.iface.MTU != incomingPort.iface.MTU {
		fmt.Print("[-] MTU values of interfaces are different. This can be a problem.")
	}

	fmt.Printf("[+] Done! Bridging...\n")

	go bridge(outgoingPort, incomingPort, OUTGOING)
	go bridge(incomingPort, outgoingPort, INCOMING)

	for {
		time.Sleep(5 * time.Second)
		//	fmt.Printf("[+] Forwarded %d packets, blocked %d packets, caught %d packets\n", forwarded, blocked, caught)\
	}

}
