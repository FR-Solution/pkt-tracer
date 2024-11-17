package nl

import (
	"os"
	"sync"
	"syscall"

	"github.com/mdlayher/socket"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// Overload netlink message for the netfilter
type NetlinkNfMsg syscall.NetlinkMessage

var _ NlNfMsg = (*NetlinkNfMsg)(nil)

func (n NetlinkNfMsg) MsgType() uint16 {
	return n.Header.Type & ^NlSubsysMask
}

func (n NetlinkNfMsg) DataOffset(offset int) []byte {
	return n.Data[offset:]
}

type (
	Nl struct {
		sock      Conn
		timeout   *unix.Timeval // timeout for receiving messages from netlink
		close     chan struct{}
		stopped   chan struct{}
		data      []chan NlData
		mu        sync.Mutex
		closeOnce sync.Once
	}
	nlReaderImpl struct {
		data chan NlData
	}
	nlOpt interface {
		apply(*Nl) error
	}

	nlOptFunc func(*Nl) error
)

var _ NetlinkWatcher = (*Nl)(nil)

func NewNetlinkWatcher(nwatchers int, proto int, opts ...nlOpt) (NetlinkWatcher, error) {
	var err error
	if nwatchers <= 0 {
		return nil, errors.WithMessage(err, "number of watchers (nwatchers) must be > 0")
	}
	watcher := &Nl{
		timeout: &unix.Timeval{ //timeout for receiving messages as default value
			Sec:  1,
			Usec: 0,
		},
		close:   make(chan struct{}),
		stopped: make(chan struct{}),
		data:    make([]chan NlData, nwatchers),
	}

	watcher.sock.Conn, err = socket.Socket(
		unix.AF_NETLINK,
		unix.SOCK_RAW,
		proto,
		"netlink",
		nil,
	)

	if err != nil {
		return nil, errors.WithMessage(err, "failed to create 'netlink' socket")
	}

	defer func() {
		if err != nil {
			_ = watcher.sock.Close()
		}
	}()

	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
	}

	if err = watcher.sock.Bind(addr); err != nil {
		return nil, errors.WithMessage(err, "failed to bind(unix.AF_NETLINK) addr to socket")
	}

	err = watcher.sock.SetsockoptInt(unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, os.Getpagesize())
	if err != nil {
		return nil, errors.WithMessage(err, "failed to set option(unix.SO_RCVBUFFORCE) to socket")
	}

	for _, o := range opts {
		if err = o.apply(watcher); err != nil {
			return nil, errors.WithMessage(err, "failed to init from options")
		}
	}
	watcher.mu.Lock()
	for i := range watcher.data {
		watcher.data[i] = make(chan NlData)
	}
	watcher.mu.Unlock()
	go watcher.run()

	return watcher, nil
}

func (n *Nl) run() {
	defer func() {
		for i := range n.data {
			close(n.data[i])
		}
		close(n.stopped)
	}()
	for {
		messages, err := n.rcv()
		select {
		case <-n.close:
			return
		default:
		}
		for i := range n.data {
			select {
			case <-n.close:
				return
			case n.data[i] <- NlData{messages, err}:
			}
		}
	}
}

func (n *nlReaderImpl) Read() chan NlData {
	return n.data
}

func (n *Nl) Reader(num int) NlReader {
	n.mu.Lock()
	defer n.mu.Unlock()
	return &nlReaderImpl{data: n.data[num]}
}

func (n *Nl) rcv() ([]syscall.NetlinkMessage, error) {
	var (
		length  int
		err     error
		rcvBuff = make([]byte, os.Getpagesize())
	)

loop:
	n.mu.Lock()
	length, err = n.sock.TryRecv(rcvBuff, n.timeout)
	n.mu.Unlock()
	if err != nil {
		var ern syscall.Errno
		if errors.As(err, &ern) {
			if ern.Temporary() {
				return nil, errors.Wrap(ErrNlReadInterrupted, err.Error())
			}
			if ern == unix.ENOBUFS || ern == unix.ENOMEM {
				return nil, errors.Wrap(ErrNlMem, err.Error())
			}
		}

		return nil, errors.WithMessage(err, "failed to read netlink data")
	}
	if length == 0 {
		rcvBuff = rcvBuff[0:]
		goto loop
	}

	messages, err := syscall.ParseNetlinkMessage(rcvBuff[:nlmsgAlign(length)])
	if err != nil {
		return nil, errors.WithMessage(err, "failed to parse netlink message")
	}

	return messages, nil
}

func (n *Nl) Close() (err error) {
	n.closeOnce.Do(func() {
		n.mu.Lock()
		err = n.sock.Close()
		n.mu.Unlock()
		close(n.close)
		<-n.stopped
	})
	return err
}

func (f nlOptFunc) apply(o *Nl) error {
	return f(o)
}

// NlWithTimeout - set timeout for receiving messages, default is 1 sec
func NlWithTimeout(t *unix.Timeval) nlOpt {
	return nlOptFunc(func(o *Nl) error {
		o.timeout = t
		return nil
	})
}

// SkWithBufLen - set receive buffer size, default is Page size
func SkWithBufLen(buflen int) nlOpt {
	return nlOptFunc(func(o *Nl) error {
		return o.sock.SetsockoptInt(unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, buflen)
	})
}

// SkWithNlMs - subscribe to netlink group
func SkWithNlMs(nlms ...int) nlOpt {
	return nlOptFunc(func(o *Nl) error {
		for _, opt := range nlms {
			if err := o.sock.SetsockoptInt(unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, opt); err != nil {
				return err
			}
		}
		return nil
	})
}
