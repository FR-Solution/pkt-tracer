package nlheaders

import (
	"encoding/binary"
	"net"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const (
	// Redirect (change route)
	ICMP_REDIRECT = 5
	// Network layer header length
	NlHeaderLen = 20
)

// TODO: add other protocol support
// Network layer header
type NlHeader struct {
	Version        uint8 // 4 bits
	IHL            uint8 // 4 bits
	DSCP           uint8 // 6 bits
	ECN            uint8 // 2 bits
	Length         uint16
	Identification uint16
	Flags          uint8  // 3 bits
	FragmentOffset uint16 // 13 bits
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	SAddr          net.IP
	DAddr          net.IP
	Options        []byte // optional, exists if IHL > 5
}

// ProtoStr - convert Protocol attribute to string
func (h *NlHeader) ProtoStr() string {
	switch h.Protocol {
	case unix.IPPROTO_TCP:
		return "tcp"

	case unix.IPPROTO_UDP:
		return "udp"

	case unix.IPPROTO_UDPLITE:
		return "udplite"

	case unix.IPPROTO_ESP:
		return "esp"

	case unix.IPPROTO_AH:
		return "ah"

	case unix.IPPROTO_ICMP:
		return "icmp"

	case unix.IPPROTO_ICMPV6:
		return "icmpv6"

	case unix.IPPROTO_COMP:
		return "comp"

	case unix.IPPROTO_DCCP:
		return "dccp"

	case unix.IPPROTO_SCTP:
		return "sctp"

	case ICMP_REDIRECT:
		return "redirect"
	}

	return "unknown"
}

// Decode - decode header from byte stream
func (h *NlHeader) Decode(b []byte) error {
	l := len(b)
	if l < NlHeaderLen {
		return errors.Errorf("incorrect NlHeader binary length=%d", l)
	}

	h.Version = (b[0] >> 4)
	h.IHL = (b[0] & 0x0f)

	h.DSCP = (b[1] >> 2)
	h.ECN = (b[1] & 0x03)

	h.Length = binary.BigEndian.Uint16(b[2:4])
	h.Identification = binary.BigEndian.Uint16(b[4:6])

	h.Flags = (b[6] >> 5)
	fob := make([]byte, 2)
	copy(fob, b[6:7])
	fob[0] = fob[0] & 0xe0
	h.FragmentOffset = binary.BigEndian.Uint16(fob)

	h.TTL = b[8]
	h.Protocol = b[9]
	h.HeaderChecksum = binary.BigEndian.Uint16(b[10:12])

	h.SAddr = make(net.IP, net.IPv4len)
	h.DAddr = make(net.IP, net.IPv4len)

	copy(h.SAddr, b[12:16])
	copy(h.DAddr, b[16:20])

	if h.IHL > 5 && l > NlHeaderLen {
		h.Options = make([]byte, l-NlHeaderLen)
		copy(h.Options, b[20:])
	}

	return nil
}
