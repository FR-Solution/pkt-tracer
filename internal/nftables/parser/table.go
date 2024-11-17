package parser

import (
	nftLib "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type (
	Table       nftLib.Table
	TableFamily nftLib.TableFamily
)

func (t TableFamily) String() string {
	switch nftLib.TableFamily(t) {
	case nftLib.TableFamilyUnspecified:
		return "unspec"
	case nftLib.TableFamilyINet:
		return "inet"
	case nftLib.TableFamilyIPv4:
		return "ip"
	case nftLib.TableFamilyIPv6:
		return "ip6"
	case nftLib.TableFamilyARP:
		return "arp"
	case nftLib.TableFamilyNetdev:
		return "netdev"
	case nftLib.TableFamilyBridge:
		return "bridge"
	}
	return "unknown"
}

func (t *Table) InitFromMsg(msg netlink.Message) error {
	t.Family = nftLib.TableFamily(msg.Data[0])

	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_TABLE_NAME:
			t.Name = ad.String()
		case unix.NFTA_TABLE_USE:
			t.Use = ad.Uint32()
		case unix.NFTA_TABLE_FLAGS:
			if t.Flags = ad.Uint32(); t.Flags != 0 { //это адов костыль
				f0 := binaryutil.NativeEndian.Uint32(binaryutil.BigEndian.PutUint32(unix.NFT_TABLE_F_DORMANT))
				if t.Flags&f0 != 0 {
					t.Flags = unix.NFT_TABLE_F_DORMANT
				}
			}
		}
	}

	return nil
}
