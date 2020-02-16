package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"ISPeer/connection"
)

const (
	OUTGOING = iota
	INCOMING = iota
)

type ACSHeader struct {
	Cookie        string
	SOAPAction    string
	ContentLength uint64
}

func generateIncomingPacket(conn connection.Connection, SYN bool, ACK bool, FIN bool, RST bool, payload []byte) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       conn.IncomingPort.Source,
		DstMAC:       conn.OutgoingPort.Source,
		EthernetType: layers.EthernetTypePPPoESession,
	}

	pppoe := layers.PPPoE{
		Version:   1,
		Type:      1,
		Code:      layers.PPPoECodeSession,
		SessionId: conn.PPPoESessionId,
	}

	ppp := layers.PPP{
		PPPType: layers.PPPTypeIPv4,
	}

	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    conn.DstIP,
		DstIP:    conn.SrcIP,
		Protocol: layers.IPProtocolTCP,
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(conn.DstPort),
		DstPort: layers.TCPPort(conn.SrcPort),
		Window:  conn.Window,
		Seq:     conn.Seq,
	}

	if ACK {
		tcp.ACK = true
		tcp.Ack = conn.Ack
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
	err := gopacket.SerializeLayers(buffer, options,
		&eth,
		&pppoe,
		&ppp,
		&ip,
		&tcp,
		gopacket.Payload(payload))

	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
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

func getHeaderValue(payload []byte) string {
	var (
		sidx = 0
		lidx = 0

		valueSide = false
		sidxSet   = false
	)
	for i, b := range payload {
		if b == '\n' || b == '\r' {
			lidx = i
			break
		}

		if !valueSide && b == ':' {
			valueSide = true
			continue
		} else if valueSide && !sidxSet {
			if b == ' ' {
				continue
			}

			sidx = i
			sidxSet = true
		}

	}

	return string(payload[sidx:lidx])
}

func extractHeaders(payload []byte) ACSHeader {
	header := ACSHeader{
		Cookie:        "",
		SOAPAction:    "",
		ContentLength: 0,
	}

	c := 0
	for i, b := range payload {
		if b != '\n' {
			continue
		}

		if len(payload) <= i+1 {
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
				cl, _ := strconv.ParseUint(getHeaderValue(payload[i+1:]), 10, 64)
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

	return header
}

func extractRequestPath(payload []byte) string {

	idx := 5
	for i, b := range payload[5:] {
		if b == ' ' {
			idx = i
			break
		}
	}

	return string(payload[5 : 5+idx])
}

func extractBody(payload []byte, length uint64) string {

	for i, b := range payload {
		if b == '\r' {
			if !bytes.Equal(payload[i+1:i+4], []byte("\n\r\n")) {
				continue
			}

			if len(payload) < i+4+int(length) {
				return ""
			}

			return string(payload[i+4 : i+4+int(length)])
		}
	}

	return ""
}

func generateHTTPResponse(resp *http.Response) ([]byte, error) {
	payload := []byte(resp.Proto)

	payload = append(payload, []byte{' '}...)
	payload = append(payload, []byte(resp.Status)...)
	payload = append(payload, []byte{'\r', '\n'}...)

	payload = append(payload, []byte("Date: ")...)
	payload = append(payload, []byte(resp.Header.Get("Date"))...)
	payload = append(payload, []byte{'\r', '\n'}...)

	payload = append(payload, []byte("Server: Apache\r\n")...)

	_, exists := resp.Header["Set-Cookie"]
	if exists {
		for _, cookie := range resp.Header["Set-Cookie"] {
			payload = append(payload, []byte("Set-Cookie: ")...)
			payload = append(payload, []byte(cookie)...)
			payload = append(payload, []byte{'\r', '\n'}...)
		}
	}

	payload = append(payload, []byte("Content-Length: ")...)
	payload = append(payload, []byte(strconv.Itoa(int(resp.ContentLength)))...)
	payload = append(payload, []byte{'\r', '\n'}...)

	payload = append(payload, []byte("Content-Type: text/xml; charset=UTF-8\r\n")...)

	payload = append(payload, []byte{'\r', '\n'}...)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	payload = append(payload, body...)

	return payload, nil
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

	lineEndIdx += idx

	cl, err := strconv.ParseUint(string(payload[idx:lineEndIdx]), 10, 64)
	if err != nil {
		fmt.Printf("THIS!: %s\n", err.Error())
		return false
	}

	body := extractBody(payload, cl)

	return body != ""
}

func forwardToHTTPS(payload []byte, responseCh chan []byte) {

	proxyURL, _ := url.Parse("socks5://127.0.0.1:8080")

	tr := http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := http.Client{
		Transport: &tr,
	}

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
		fmt.Printf("[-] Error while generating HTTP response: %s\n", err.Error())
		return
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Printf("[-] Unexpected status code returned: %d\n", resp.StatusCode)
		fmt.Printf("%s", string(resPayload))
	}

	responseCh <- resPayload

	close(responseCh)
}

func handleTLSProxy(packetCh chan *gopacket.Packet, pppoeSessionId uint16, outgoingPort connection.BridgePort, incomingPort connection.BridgePort) {

	outgoingChain := make(map[uint16]connection.Connection)

	for {
		packet := <-packetCh

		tcp, _ := (*packet).Layer(layers.LayerTypeTCP).(*layers.TCP)
		ip, _ := (*packet).Layer(layers.LayerTypeIPv4).(*layers.IPv4)

		conn, exists := outgoingChain[uint16(tcp.SrcPort)]

		if !exists { // new connection
			if !tcp.SYN {
				fmt.Printf("[-] The connection is not in its inital state but we don't know about it. Ignoring...\n")
				// TODO: send RST packet
				continue
			}

			fmt.Printf("[+] SYN received. Sending SYNACK...\n")

			conn := connection.Connection{
				SrcPort:        uint16(tcp.SrcPort),
				DstPort:        uint16(tcp.DstPort),
				SrcIP:          ip.SrcIP,
				DstIP:          ip.DstIP,
				State:          connection.INITIALIZED,
				Seq:            tcp.Ack,
				Ack:            tcp.Seq + 1,
				Window:         tcp.Window,
				PPPoESessionId: pppoeSessionId,
				ResponseBuffer: make([]byte, 0),
				IncomingPort:   incomingPort,
				OutgoingPort:   outgoingPort,
			}

			outgoingChain[conn.SrcPort] = conn

			packetData, err := generateIncomingPacket(conn, true, true, false, false, nil) // SYNACK
			if err != nil {
				fmt.Printf("[-] Error while generating packet: %s\n", err.Error())
				continue
			}
			err = outgoingPort.Handle.WritePacketData(packetData)
			if err != nil {
				fmt.Printf("Error while sending SYNACK packet: %s\n", err.Error())
				continue
			}

			fmt.Printf("[+] SYNACK sent\n")

			continue

		} else if tcp.CWR || tcp.ECE || tcp.NS || tcp.URG {
			fmt.Printf("[-] Unsupported tcp flag received! Ignoring...\n")
			continue
		} else if tcp.RST {
			conn.State = connection.COMPLETED

			outgoingChain[conn.SrcPort] = conn

			fmt.Printf("[+] RST received. connection.Connection is terminated\n")
			continue

		}

		if tcp.ACK && conn.State == connection.INITIALIZED { // threeway handshake
			conn.State = connection.ESTABLISHED

			fmt.Printf("[+] Threeway handshake completed\n")

		} else if conn.State >= connection.TERMINATED { // connection completed
			if conn.State == connection.TERMINATED {
				conn.State = connection.COMPLETED
				outgoingChain[conn.SrcPort] = conn
				continue
			}

			fmt.Printf("[-] Packet received for completed connection. Sending RST...\n")

			packetData, err := generateIncomingPacket(conn, false, false, false, true, nil) // RST
			if err != nil {
				fmt.Printf("[-] Error while generating packet: %s\n", err.Error())
				continue
			}

			err = conn.OutgoingPort.Handle.WritePacketData(packetData)
			if err != nil {
				fmt.Printf("Error while sending ACK packet: %s\n", err.Error())
				continue
			}

			fmt.Printf("[+] RST sent\n")
			continue
		}

		payload := tcp.Payload
		conn.Seq = tcp.Ack
		conn.Ack = tcp.Seq + uint32(len(payload))

		if len(payload) == 0 && !tcp.FIN { // ACK without payload received
			outgoingChain[conn.SrcPort] = conn
			continue
		}

		if tcp.FIN { // FIN received
			conn.Ack++

			fin := false
			if conn.State == connection.ESTABLISHED {
				conn.State = connection.TERMINATED
				fmt.Printf("[+] Received FIN from target. connection.Connection is terminated, sending FINACK\n")

				fin = true
			} else if conn.State == connection.TERMINATING {
				conn.State = connection.COMPLETED
				tcp.FIN = false
				fmt.Printf("[+] Received FINACK from target. connection.Connection is terminated, sending ACK\n")
			}

			packetData, err := generateIncomingPacket(conn, false, true, fin, false, nil)
			if err != nil {
				fmt.Printf("[-] Error while generating packet: %s\n", err.Error())
				continue
			}

			err = outgoingPort.Handle.WritePacketData(packetData)
			if err != nil {
				fmt.Printf("[-] Error while sending packet: %s\n", err.Error())
				continue
			}

			outgoingChain[conn.SrcPort] = conn
			fmt.Printf("[+] Sent\n")
			continue
		}

		// payload received
		var responseCh chan []byte
		mPayload, err := processOutgoing(*packet, false)
		if err != nil {
			fmt.Printf("[-] Unable to modify payload, continuing with unmodified packet: %s\n", err.Error())
			mPayload = payload
		}

		conn.ResponseBuffer = append(conn.ResponseBuffer, mPayload...)

		if isCompleteHTTPPayload(conn.ResponseBuffer) { // it is ok to forward responseBuffer now
			responseCh = make(chan []byte)

			go forwardToHTTPS(conn.ResponseBuffer, responseCh)

			conn.State = connection.WAITING
		}

		packetData, err := generateIncomingPacket(conn, false, true, false, false, nil)
		if err != nil {
			fmt.Printf("[-] Error while generating packet: %s\n", err.Error())
			continue
		}

		err = outgoingPort.Handle.WritePacketData(packetData)
		if err != nil {
			fmt.Printf("[-] Error while sending ACK packet: %s\n", err.Error())
			continue
		}

		outgoingChain[conn.SrcPort] = conn
		fmt.Printf("[+] Sent\n")

		if conn.State != connection.WAITING {
			continue
		}

		// responseBuffer forwarded
		// now wait response from https proxy
		resPayload, ok := <-responseCh

		if !ok {
			fmt.Printf("[-] Couldn't receive http response\n")
			// TODO: terminate connection
			continue
		}

		packetData, err = generateIncomingPacket(conn, false, true, false, false, resPayload)
		if err != nil {
			fmt.Printf("[-] Error while generating packet from http response: %s\n", err.Error())
			continue
		}

		if len(packetData) <= outgoingPort.Iface.MTU {
			err = outgoingPort.Handle.WritePacketData(packetData)
			if err != nil {
				fmt.Printf("[-] Error while forwarding http response to %s: %s\n", outgoingPort.Iface.Name, err.Error())
				// TODO: terminate connection
				continue
			}
		} else {
			fmt.Printf("[+] Fragmenting packet...\n")
			packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)

			err = fragmentAndSend(OUTGOING, &packet, outgoingPort)
			if err != nil {
				fmt.Printf("[-] Error while fragmenting packet: %s\n", err.Error())
				return
			}
		}

		conn.Seq += uint32(len(packetData))
		packetData, err = generateIncomingPacket(conn, false, true, true, false, nil)
		if err != nil {
			fmt.Printf("[-] Error while generating FINACK packet: %s\n", err.Error())
			continue
		}

		err = outgoingPort.Handle.WritePacketData(packetData)
		if err != nil {
			fmt.Printf("[-] Error while sending FINACK to %s: %s\n", outgoingPort.Iface.Name, err.Error())
			continue
		}

		conn.State = connection.TERMINATING
		conn.Seq++
		outgoingChain[conn.SrcPort] = conn
	}
}

func fragmentAndSend(label int, packet *gopacket.Packet, port connection.BridgePort) error {

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

func bridge(outgoingPort connection.BridgePort, incomingPort connection.BridgePort, label int, packetCh chan *gopacket.Packet) {

	pppoeSessionId := uint16(0)

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

		if label == INCOMING && pppoeSessionId == 0 {
			pppoeLayer := packet.Layer(layers.LayerTypePPPoE)

			if pppoeLayer != nil {
				pppoe, _ := pppoeLayer.(*layers.PPPoE)

				if pppoe.Code == layers.PPPoECodePADS {
					pppoeSessionId = pppoe.SessionId
					fmt.Printf("[+] Retreived PPPoE Session ID: %d. Starting proxy...\n", pppoeSessionId)

					go handleTLSProxy(packetCh, pppoeSessionId, incomingPort, outgoingPort)
				}
			}
		}

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
				} else if tcp.DstPort == 8016 {
					packetCh <- &packet
					continue
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

func initPort(ifaceName string, mac net.HardwareAddr) (connection.BridgePort, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return connection.BridgePort{}, fmt.Errorf("Error retrieving interface %s: %s", ifaceName, err.Error())
	}

	handle, err := initHandle(iface, true)
	if err != nil {
		return connection.BridgePort{}, fmt.Errorf("Error while initializing handle: %s", err.Error())
	}

	return connection.BridgePort{iface, handle, mac}, nil
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

	packetCh := make(chan *gopacket.Packet)

	fmt.Printf("[+] Done! Bridging...\n")

	go bridge(outgoingPort, incomingPort, OUTGOING, packetCh)
	bridge(incomingPort, outgoingPort, INCOMING, packetCh)
}
