package connection

import (
	"net"

	"github.com/google/gopacket/pcap"
)

type BridgePort struct {
	Iface  *net.Interface
	Handle *pcap.Handle
	Source net.HardwareAddr
}

const (
	INITIALIZED = iota
	ESTABLISHED = iota
	WAITING     = iota
	TERMINATING = iota
	TERMINATED  = iota
	COMPLETED   = iota
)

// TODO: add lastactivetime/timeout
type Connection struct {
	SrcPort        uint16
	DstPort        uint16
	SrcIP          net.IP
	DstIP          net.IP
	State          int
	Seq            uint32
	Ack            uint32
	Window         uint16
	PPPoESessionId uint16
	ResponseBuffer []byte
	OutgoingPort   BridgePort
	IncomingPort   BridgePort
}
