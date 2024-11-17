package nftrace

import (
	"encoding/binary"

	model "github.com/wildberries-tech/pkt-tracer/internal/models/nltrace"
	"github.com/wildberries-tech/pkt-tracer/internal/nl/nlheaders"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type NftnlTrace struct {
	Table      string
	Chain      string
	JumpTarget string
	RuleHandle uint64
	Lh         nlheaders.LlHeader
	Nh         nlheaders.NlHeader
	Th         nlheaders.TlHeader
	Family     byte
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
}

func (tr *NftnlTrace) ToModel() model.NetlinkTrace {
	return model.NetlinkTrace{
		Table:      tr.Table,
		Chain:      tr.Chain,
		JumpTarget: tr.JumpTarget,
		RuleHandle: tr.RuleHandle,
		Lh:         tr.Lh,
		Nh:         tr.Nh,
		Th:         tr.Th,
		Family:     model.FamilyTable(tr.Family),
		Type:       tr.Type,
		Id:         tr.Id,
		Iif:        tr.Iif,
		Oif:        tr.Oif,
		Mark:       tr.Mark,
		Verdict:    tr.Verdict,
		Nfproto:    tr.Nfproto,
		Policy:     tr.Policy,
		Iiftype:    tr.Iiftype,
		Oiftype:    tr.Oiftype,
		Flags:      tr.Flags,
	}
}

func (tr *NftnlTrace) InitFromMsg(msg netlink.Message) error {
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_TRACE_ID:
			tr.Id = ad.Uint32()
			tr.Flags |= (1 << NFTNL_TRACE_ID)
		case unix.NFTA_TRACE_TYPE:
			tr.Type = ad.Uint32()
			tr.Flags |= (1 << NFTNL_TRACE_TYPE)
		case unix.NFTA_TRACE_TABLE:
			tr.Table = ad.String()
			tr.Flags |= (1 << NFTNL_TRACE_TABLE)
		case unix.NFTA_TRACE_CHAIN:
			tr.Chain = ad.String()
			tr.Flags |= (1 << NFTNL_TRACE_CHAIN)
		case unix.NFTA_TRACE_VERDICT:
			ad, err := netlink.NewAttributeDecoder(ad.Bytes())
			if err != nil {
				return err
			}
			ad.ByteOrder = binary.BigEndian
			for ad.Next() {
				switch ad.Type() {
				case unix.NFTA_VERDICT_CODE:
					tr.Verdict = ad.Uint32()
					tr.Flags |= (1 << NFTNL_TRACE_VERDICT)
				case unix.NFTA_VERDICT_CHAIN:
					if int32(tr.Verdict) == unix.NFT_GOTO || //nolint:gosec
						int32(tr.Verdict) == unix.NFT_JUMP { //nolint:gosec
						tr.JumpTarget = ad.String()
						tr.Flags |= (1 << NFTNL_TRACE_JUMP_TARGET)
					}
				}
			}
		case unix.NFTA_TRACE_IIFTYPE:
			tr.Iiftype = ad.Uint16()
			tr.Flags |= (1 << NFTNL_TRACE_IIFTYPE)
		case unix.NFTA_TRACE_IIF:
			tr.Iif = ad.Uint32()
			tr.Flags |= (1 << NFTNL_TRACE_IIF)
		case unix.NFTA_TRACE_OIFTYPE:
			tr.Oiftype = ad.Uint16()
			tr.Flags |= (1 << NFTNL_TRACE_OIFTYPE)
		case unix.NFTA_TRACE_OIF:
			tr.Oif = ad.Uint32()
			tr.Flags |= (1 << NFTNL_TRACE_OIF)
		case unix.NFTA_TRACE_MARK:
			tr.Mark = ad.Uint32()
			tr.Flags |= (1 << NFTNL_TRACE_MARK)
		case unix.NFTA_TRACE_RULE_HANDLE:
			tr.RuleHandle = ad.Uint64()
			tr.Flags |= (1 << NFTNL_TRACE_RULE_HANDLE)
		case unix.NFTA_TRACE_LL_HEADER:
			if err := tr.Lh.Decode(ad.Bytes()); err != nil {
				return err
			}
			tr.Flags |= (1 << NFTNL_TRACE_LL_HEADER)
		case unix.NFTA_TRACE_NETWORK_HEADER:
			if err := tr.Nh.Decode(ad.Bytes()); err != nil {
				return err
			}
			tr.Flags |= (1 << NFTNL_TRACE_NETWORK_HEADER)
		case unix.NFTA_TRACE_TRANSPORT_HEADER:
			if err := tr.Th.Decode(ad.Bytes()); err != nil {
				return err
			}
			tr.Flags |= (1 << NFTNL_TRACE_TRANSPORT_HEADER)
		case unix.NFTA_TRACE_NFPROTO:
			tr.Nfproto = ad.Uint32()
			tr.Flags |= (1 << NFTNL_TRACE_NFPROTO)
		case unix.NFTA_TRACE_POLICY:
			tr.Policy = ad.Uint32()
			tr.Flags |= (1 << NFTNL_TRACE_POLICY)
		}
	}
	tr.Family = msg.Data[0]
	tr.Flags |= (1 << NFTNL_TRACE_FAMILY)
	return nil
}
