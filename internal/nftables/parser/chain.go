package parser

import (
	"encoding/binary"

	nftLib "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type (
	Chain         nftLib.Chain
	ChainHook     nftLib.ChainHook
	ChainPriority nftLib.ChainPriority
	ChainPolicy   nftLib.ChainPolicy
)

func (c ChainHook) String() string {
	switch nftLib.ChainHook(c) {
	case *nftLib.ChainHookPrerouting:
		return "prerouting"
	case *nftLib.ChainHookInput:
		return "input"
	case *nftLib.ChainHookForward:
		return "forward"
	case *nftLib.ChainHookOutput:
		return "output"
	case *nftLib.ChainHookPostrouting:
		return "postrouting"
	case *nftLib.ChainHookIngress:
		return "ingress"
	}
	return "unknown" //nolint:goconst
}

func (c ChainPriority) String() string {
	switch nftLib.ChainPriority(c) {
	case *nftLib.ChainPriorityFirst:
		return "first"
	case *nftLib.ChainPriorityConntrackDefrag:
		return "conntrack-defrag"
	case *nftLib.ChainPriorityRaw:
		return "raw"
	case *nftLib.ChainPrioritySELinuxFirst:
		return "se-linux-first"
	case *nftLib.ChainPriorityConntrack:
		return "conntrack"
	case *nftLib.ChainPriorityMangle:
		return "mangle"
	case *nftLib.ChainPriorityNATDest:
		return "natd"
	case *nftLib.ChainPriorityFilter:
		return "filter"
	case *nftLib.ChainPrioritySecurity:
		return "security"
	case *nftLib.ChainPriorityNATSource:
		return "nats"
	case *nftLib.ChainPrioritySELinuxLast:
		return "se-linux-last"
	case *nftLib.ChainPriorityConntrackHelper:
		return "conntrack-helper"
	case *nftLib.ChainPriorityConntrackConfirm:
		return "conntrack-confirm"
	case *nftLib.ChainPriorityLast:
		return "last"
	}
	return "unknown"
}

func (p ChainPolicy) String() string {
	switch nftLib.ChainPolicy(p) {
	case nftLib.ChainPolicyDrop:
		return "drop"
	case nftLib.ChainPolicyAccept:
		return "accept"
	}
	return "unknown"
}

func (c *Chain) InitFromMsg(msg netlink.Message) error {
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_CHAIN_NAME:
			c.Name = ad.String()
		case unix.NFTA_TABLE_NAME:
			c.Table = &nftLib.Table{Name: ad.String()}
			// msg[0] carries TableFamily byte indicating whether it is IPv4, IPv6 or something else
			c.Table.Family = nftLib.TableFamily(msg.Data[0])
		case unix.NFTA_CHAIN_TYPE:
			c.Type = nftLib.ChainType(ad.String())
		case unix.NFTA_CHAIN_POLICY:
			policy := nftLib.ChainPolicy(binaryutil.BigEndian.Uint32(ad.Bytes()))
			c.Policy = &policy
		case unix.NFTA_CHAIN_HOOK:
			ad.Do(func(b []byte) error {
				c.Hooknum, c.Priority, err = hookFromMsg(b)
				return err
			})
		}
	}

	return nil
}

func hookFromMsg(b []byte) (*nftLib.ChainHook, *nftLib.ChainPriority, error) {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return nil, nil, err
	}

	ad.ByteOrder = binary.BigEndian

	var hooknum nftLib.ChainHook
	var prio nftLib.ChainPriority

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_HOOK_HOOKNUM:
			hooknum = nftLib.ChainHook(ad.Uint32())
		case unix.NFTA_HOOK_PRIORITY:
			prio = nftLib.ChainPriority(ad.Uint32()) //nolint:gosec
		}
	}

	return &hooknum, &prio, nil
}
