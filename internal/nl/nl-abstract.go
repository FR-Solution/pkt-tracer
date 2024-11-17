package nl

import (
	"syscall"

	"github.com/pkg/errors"
)

const (
	// Align nl message to boundary
	nlmsgAlignTo = 4

	// Nl subsystem message mask
	NlSubsysMask uint16 = 0xf00

	// Offset attribute data in the nft netlink group message
	NlNftAttrOffset = 4

	// Offset attribute data in the RTM netlink group message
	NlRtmAttrOffset = 16

	// Socket buffer length 16 MB
	SockBufLen16MB = (1 << 24)
)

func nlmsgAlign(len int) int {
	return ((len) + nlmsgAlignTo - 1) & ^(nlmsgAlignTo - 1)
}

type (
	NlData struct {
		Messages []syscall.NetlinkMessage
		Err      error
	}
	NlReader interface {
		Read() chan NlData
	}
	// NetlinkWatcher netlink watch streamer
	NetlinkWatcher interface {
		Reader(num int) NlReader
		Close() error
	}

	// NlNfMsg netlink netfilter message type
	NlNfMsg interface {
		MsgType() uint16
		DataOffset(int) []byte
	}
)

var (
	ErrNlDataNotReady    = errors.New("nl data not ready")
	ErrNlReadInterrupted = errors.New("nl read operation interrupted")
	ErrNlMem             = errors.New("memory failed")
)
