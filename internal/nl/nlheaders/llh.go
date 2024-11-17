package nlheaders

import (
	"encoding/binary"
	"net"

	"github.com/pkg/errors"
)

const (
	// MAC address length
	EthMACLength = 6
	// Link layer header length
	LlHeaderLen = 14
)

// Link layer header
type LlHeader struct {
	SAddr    net.HardwareAddr
	DAddr    net.HardwareAddr
	Protocol uint16
}

func (h *LlHeader) Decode(b []byte) error {
	if l := len(b); l != LlHeaderLen {
		return errors.Errorf("incorrect LlHeader binary length=%d", l)
	}

	h.SAddr = make(net.HardwareAddr, EthMACLength)
	h.DAddr = make(net.HardwareAddr, EthMACLength)

	copy(h.DAddr, b[:6])
	copy(h.SAddr, b[6:12])

	h.Protocol = binary.BigEndian.Uint16(b[12:])

	return nil
}
