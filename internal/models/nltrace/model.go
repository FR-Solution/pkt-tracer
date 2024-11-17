package nltrace

import (
	"time"

	"github.com/wildberries-tech/pkt-tracer/internal/nl/nlheaders"

	"golang.org/x/sys/unix"
)

type FamilyTable byte

func (f FamilyTable) String() string {
	switch f {
	case unix.NFPROTO_IPV4:
		return "ip"

	case unix.NFPROTO_IPV6:
		return "ip6"

	case unix.NFPROTO_INET:
		return "inet"

	case unix.NFPROTO_NETDEV:
		return "netdev"

	case unix.NFPROTO_ARP:
		return "arp"

	case unix.NFPROTO_BRIDGE:
		return "bridge"
	}

	return "unknown"
}

type NetlinkTrace struct {
	Table      string
	Chain      string
	JumpTarget string
	RuleHandle uint64
	Lh         nlheaders.LlHeader
	Nh         nlheaders.NlHeader
	Th         nlheaders.TlHeader
	Family     FamilyTable
	Type       uint32
	Id         uint32
	Iif        uint32
	Oif        uint32
	Mark       uint32
	Verdict    uint32
	Nfproto    uint32
	Policy     uint32
	Iiftype    uint16
	Oiftype    uint16
	Flags      uint32
	At         time.Time
}
