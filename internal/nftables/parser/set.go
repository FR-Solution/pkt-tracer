package parser

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	nfte "github.com/wildberries-tech/pkt-tracer/internal/nftables/encoders"

	nftLib "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	baseDec = 10
	baseHex = 16
)

type (
	SetDatatype nftLib.SetDatatype

	SetElement nftLib.SetElement

	Set struct {
		*nftLib.Set
		Elems []nftLib.SetElement
	}
	SetElem struct {
		Set  *nftLib.Set
		Elem nftLib.SetElement
	}
)

const (
	MagicTypeInvalid uint32 = iota
	MagicTypeVerdict
	MagicTypeNFProto
	MagicTypeBitmask
	MagicTypeInteger
	MagicTypeString
	MagicTypeLLAddr
	MagicTypeIPAddr
	MagicTypeIP6Addr
	MagicTypeEtherAddr
	MagicTypeEtherType
	MagicTypeARPOp
	MagicTypeInetProto
	MagicTypeInetService
	MagicTypeICMPType
	MagicTypeTCPFlag
	MagicTypeDCCPPktType
	MagicTypeMHType
	MagicTypeTime
	MagicTypeMark
	MagicTypeIFIndex
	MagicTypeARPHRD
	MagicTypeRealm
	MagicTypeClassID
	MagicTypeUID
	MagicTypeGID
	MagicTypeCTState
	MagicTypeCTDir
	MagicTypeCTStatus
	MagicTypeICMP6Type
	MagicTypeCTLabel
	MagicTypePktType
	MagicTypeICMPCode
	MagicTypeICMPV6Code
	MagicTypeICMPXCode
	MagicTypeDevGroup
	MagicTypeDSCP
	MagicTypeECN
	MagicTypeFIBAddr
	MagicTypeBoolean
	MagicTypeCTEventBit
	MagicTypeIFName
	MagicTypeIGMPType
	MagicTypeTimeDate
	MagicTypeTimeHour
	MagicTypeTimeDay
	MagicTypeCGroupV2
)

var nftDatatypesByMagic = map[uint32]nftLib.SetDatatype{
	MagicTypeVerdict:     nftLib.TypeVerdict,
	MagicTypeNFProto:     nftLib.TypeNFProto,
	MagicTypeBitmask:     nftLib.TypeBitmask,
	MagicTypeInteger:     nftLib.TypeInteger,
	MagicTypeString:      nftLib.TypeString,
	MagicTypeLLAddr:      nftLib.TypeLLAddr,
	MagicTypeIPAddr:      nftLib.TypeIPAddr,
	MagicTypeIP6Addr:     nftLib.TypeIP6Addr,
	MagicTypeEtherAddr:   nftLib.TypeEtherAddr,
	MagicTypeEtherType:   nftLib.TypeEtherType,
	MagicTypeARPOp:       nftLib.TypeARPOp,
	MagicTypeInetProto:   nftLib.TypeInetProto,
	MagicTypeInetService: nftLib.TypeInetService,
	MagicTypeICMPType:    nftLib.TypeICMPType,
	MagicTypeTCPFlag:     nftLib.TypeTCPFlag,
	MagicTypeDCCPPktType: nftLib.TypeDCCPPktType,
	MagicTypeMHType:      nftLib.TypeMHType,
	MagicTypeTime:        nftLib.TypeTime,
	MagicTypeMark:        nftLib.TypeMark,
	MagicTypeIFIndex:     nftLib.TypeIFIndex,
	MagicTypeARPHRD:      nftLib.TypeARPHRD,
	MagicTypeRealm:       nftLib.TypeRealm,
	MagicTypeClassID:     nftLib.TypeClassID,
	MagicTypeUID:         nftLib.TypeUID,
	MagicTypeGID:         nftLib.TypeGID,
	MagicTypeCTState:     nftLib.TypeCTState,
	MagicTypeCTDir:       nftLib.TypeCTDir,
	MagicTypeCTStatus:    nftLib.TypeCTStatus,
	MagicTypeICMP6Type:   nftLib.TypeICMP6Type,
	MagicTypeCTLabel:     nftLib.TypeCTLabel,
	MagicTypePktType:     nftLib.TypePktType,
	MagicTypeICMPCode:    nftLib.TypeICMPCode,
	MagicTypeICMPV6Code:  nftLib.TypeICMPV6Code,
	MagicTypeICMPXCode:   nftLib.TypeICMPXCode,
	MagicTypeDevGroup:    nftLib.TypeDevGroup,
	MagicTypeDSCP:        nftLib.TypeDSCP,
	MagicTypeECN:         nftLib.TypeECN,
	MagicTypeFIBAddr:     nftLib.TypeFIBAddr,
	MagicTypeBoolean:     nftLib.TypeBoolean,
	MagicTypeCTEventBit:  nftLib.TypeCTEventBit,
	MagicTypeIFName:      nftLib.TypeIFName,
	MagicTypeIGMPType:    nftLib.TypeIGMPType,
	MagicTypeTimeDate:    nftLib.TypeTimeDate,
	MagicTypeTimeHour:    nftLib.TypeTimeHour,
	MagicTypeTimeDay:     nftLib.TypeTimeDay,
	MagicTypeCGroupV2:    nftLib.TypeCGroupV2,
}

func (s *SetElement) decode(fam byte) func(b []byte) error {
	return func(b []byte) error {
		ad, err := netlink.NewAttributeDecoder(b)
		if err != nil {
			return fmt.Errorf("failed to create nested attribute decoder: %v", err)
		}
		ad.ByteOrder = binary.BigEndian

		for ad.Next() {
			switch ad.Type() {
			case unix.NFTA_SET_ELEM_KEY:
				s.Key, err = decodeElement(ad.Bytes())
				if err != nil {
					return err
				}
			case nftLib.NFTA_SET_ELEM_KEY_END:
				s.KeyEnd, err = decodeElement(ad.Bytes())
				if err != nil {
					return err
				}
			case unix.NFTA_SET_ELEM_DATA:
				s.Val, err = decodeElement(ad.Bytes())
				if err != nil {
					return err
				}
			case unix.NFTA_SET_ELEM_FLAGS:
				flags := ad.Uint32()
				s.IntervalEnd = (flags & unix.NFT_SET_ELEM_INTERVAL_END) != 0
			case unix.NFTA_SET_ELEM_TIMEOUT:
				s.Timeout = time.Millisecond * time.Duration(ad.Uint64()) //nolint:gosec
			case unix.NFTA_SET_ELEM_EXPIRATION:
				s.Expires = time.Millisecond * time.Duration(ad.Uint64()) //nolint:gosec
			case unix.NFTA_SET_ELEM_EXPR:
				elems, err := ParseExprBytesFunc(fam, ad, ad.Bytes())
				if err != nil {
					return err
				}

				for _, elem := range elems {
					switch item := elem.(type) {
					case *expr.Counter:
						s.Counter = item
					}
				}
			}
		}
		return ad.Err()
	}
}

func decodeElement(d []byte) ([]byte, error) {
	ad, err := netlink.NewAttributeDecoder(d)
	if err != nil {
		return nil, fmt.Errorf("failed to create nested attribute decoder: %v", err)
	}
	ad.ByteOrder = binary.BigEndian
	var b []byte
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_SET_ELEM_KEY:
			fallthrough
		case unix.NFTA_SET_ELEM_DATA:
			b = ad.Bytes()
		}
	}
	if err := ad.Err(); err != nil {
		return nil, err
	}
	return b, nil
}

func (set *Set) InitFromMsg(msg netlink.Message) error {
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	if set.Set == nil {
		set.Set = new(nftLib.Set)
	}
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_SET_NAME:
			set.Name = ad.String()
		case unix.NFTA_SET_TABLE:
			set.Table = &nftLib.Table{Name: ad.String()}
			// msg[0] carries TableFamily byte indicating whether it is IPv4, IPv6 or something else
			set.Table.Family = nftLib.TableFamily(msg.Data[0])
		case unix.NFTA_SET_ID:
			set.ID = binary.BigEndian.Uint32(ad.Bytes())
		case unix.NFTA_SET_TIMEOUT:
			set.Timeout = time.Millisecond * time.Duration(binary.BigEndian.Uint64(ad.Bytes())) //nolint:gosec
			set.HasTimeout = true
		case unix.NFTA_SET_FLAGS:
			flags := ad.Uint32()
			set.Constant = (flags & unix.NFT_SET_CONSTANT) != 0
			set.Anonymous = (flags & unix.NFT_SET_ANONYMOUS) != 0
			set.Interval = (flags & unix.NFT_SET_INTERVAL) != 0
			set.IsMap = (flags & unix.NFT_SET_MAP) != 0
			set.HasTimeout = (flags & unix.NFT_SET_TIMEOUT) != 0
			set.Concatenation = (flags & nftLib.NFT_SET_CONCAT) != 0
		case unix.NFTA_SET_KEY_TYPE:
			nftMagic := ad.Uint32()
			dt, err := parseSetDatatype(nftMagic)
			if err != nil {
				return fmt.Errorf("could not determine data type: %w", err)
			}
			set.KeyType = dt
		case unix.NFTA_SET_KEY_LEN:
			set.KeyType.Bytes = binary.BigEndian.Uint32(ad.Bytes())
		case unix.NFTA_SET_DATA_TYPE:
			nftMagic := ad.Uint32()
			// Special case for the data type verdict, in the message it is stored as 0xffffff00 but it is defined as 1
			if nftMagic == 0xffffff00 { //nolint:mnd
				set.KeyType = nftLib.TypeVerdict
				break
			}
			dt, err := parseSetDatatype(nftMagic)
			if err != nil {
				return fmt.Errorf("could not determine data type: %w", err)
			}
			set.DataType = dt
		case unix.NFTA_SET_DATA_LEN:
			set.DataType.Bytes = binary.BigEndian.Uint32(ad.Bytes())
		}
	}
	return nil
}

func parseSetDatatype(magic uint32) (nftLib.SetDatatype, error) {
	types := make([]nftLib.SetDatatype, 0, 32/nftLib.SetConcatTypeBits) //nolint:mnd
	for magic != 0 {
		t := magic & nftLib.SetConcatTypeMask
		magic = magic >> nftLib.SetConcatTypeBits
		dt, ok := nftDatatypesByMagic[t]
		if !ok {
			return nftLib.TypeInvalid, fmt.Errorf("could not determine data type %+v", dt)
		}
		// Because we start with the last type, we insert the later types at the front.
		types = append([]nftLib.SetDatatype{dt}, types...)
	}

	dt, err := nftLib.ConcatSetType(types...)
	if err != nil {
		return nftLib.TypeInvalid, fmt.Errorf("could not create data type: %w", err)
	}
	return dt, nil
}

func (set *Set) GetElementsFromMsg(msg netlink.Message) error {
	fam := msg.Data[0]
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	if set.Set == nil {
		set.Set = new(nftLib.Set)
	}
	for ad.Next() {
		b := ad.Bytes()
		switch ad.Type() {
		case unix.NFTA_SET_ELEM_LIST_TABLE:
			set.Table = &nftLib.Table{Name: ad.String(), Family: nftLib.TableFamily(fam)}
		case unix.NFTA_SET_ELEM_LIST_SET:
			set.Name = ad.String()
		case unix.NFTA_SET_ELEM_LIST_SET_ID:
			set.ID = ad.Uint32()
		case unix.NFTA_SET_ELEM_LIST_ELEMENTS:
			ad, err := netlink.NewAttributeDecoder(b)
			if err != nil {
				return err
			}
			ad.ByteOrder = binary.BigEndian
			for ad.Next() {
				var elem SetElement
				if ad.Type() == unix.NFTA_LIST_ELEM {
					ad.Do(elem.decode(fam))
					if ad.Err() != nil {
						return ad.Err()
					}
					set.Elems = append(set.Elems, nftLib.SetElement(elem))
				}
			}
		}
	}

	return nil
}

func (s Set) Flags() (flags []string) {
	if s.Constant {
		flags = append(flags, "constant")
	}

	if s.Anonymous {
		flags = append(flags, "anonymous")
	}

	if s.Interval {
		flags = append(flags, "interval")
	}

	if s.IsMap {
		flags = append(flags, "map")
	}

	if s.HasTimeout {
		flags = append(flags, "timeout")
	}

	if s.Concatenation {
		flags = append(flags, "concatenation")
	}

	return
}

func (s Set) String() string {
	var (
		sb         = strings.Builder{}
		validElems []nftLib.SetElement
	)
	for _, elem := range s.Elems {
		if elem.IntervalEnd {
			continue
		}
		if len(validElems) > 0 {
			sb.WriteByte(',')
		}
		validElems = append(validElems, elem)
		sb.WriteString(SetElem{Set: s.Set, Elem: elem}.String())
	}
	return sb.String()
}

func (s SetElem) String() string {
	switch s.Set.KeyType {
	case nftLib.TypeVerdict,
		nftLib.TypeString,
		nftLib.TypeIFName:
		return nfte.RawBytes(s.Elem.Key).String()
	case nftLib.TypeIPAddr,
		nftLib.TypeIP6Addr:
		return nfte.RawBytes(s.Elem.Key).Ip().String()
	case nftLib.TypeBitmask,
		nftLib.TypeLLAddr,
		nftLib.TypeEtherAddr,
		nftLib.TypeTCPFlag,
		nftLib.TypeMark,
		nftLib.TypeUID,
		nftLib.TypeGID:
		return nfte.RawBytes(s.Elem.Key).Text(baseHex)
	}
	return nfte.RawBytes(s.Elem.Key).Text(baseDec)
}
