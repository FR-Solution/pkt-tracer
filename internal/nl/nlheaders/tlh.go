package nlheaders

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

// Transport layer header length
const TlHeaderLen = 8

// Transport layer header
type TlHeader struct {
	SPort    uint16
	DPort    uint16
	Length   uint16
	Checksum uint16
	Data     []byte
}

func (h *TlHeader) Decode(b []byte) error {
	if l := len(b); l < TlHeaderLen {
		return errors.Errorf("incorrect TlHeader binary length=%d", l)
	}

	h.SPort = binary.BigEndian.Uint16(b[:2])
	h.DPort = binary.BigEndian.Uint16(b[2:4])
	h.Length = binary.BigEndian.Uint16(b[4:6])
	h.Checksum = binary.BigEndian.Uint16(b[6:8])

	l := len(b[8:])
	if l != 0 {
		h.Data = make([]byte, l)
		copy(h.Data, b[8:])
	}

	return nil
}
