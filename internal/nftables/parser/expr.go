package parser

import (
	"encoding/binary"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

var (
	ParseExprBytesFunc func(fam byte, ad *netlink.AttributeDecoder, b []byte) ([]interface{}, error)
	ParseExprMsgFunc   func(fam byte, b []byte) ([]interface{}, error)
)

func init() {
	ParseExprBytesFunc = func(fam byte, ad *netlink.AttributeDecoder, b []byte) ([]interface{}, error) {
		exprs, err := exprsFromBytes(fam, ad)
		if err != nil {
			return nil, err
		}
		result := make([]interface{}, len(exprs))
		for idx, expr := range exprs {
			result[idx] = expr
		}
		return result, nil
	}
	ParseExprMsgFunc = func(fam byte, b []byte) ([]interface{}, error) {
		ad, err := netlink.NewAttributeDecoder(b)
		if err != nil {
			return nil, err
		}
		ad.ByteOrder = binary.BigEndian
		var exprs []interface{}
		for ad.Next() {
			e, err := ParseExprBytesFunc(fam, ad, b)
			if err != nil {
				return e, err
			}
			exprs = append(exprs, e...)
		}
		return exprs, ad.Err()
	}
}

//nolint:gocyclo
func exprsFromBytes(fam byte, ad *netlink.AttributeDecoder) ([]expr.Any, error) {
	var exprs []expr.Any
	ad.Do(func(b []byte) error {
		ad, err := netlink.NewAttributeDecoder(b)
		if err != nil {
			return err
		}
		ad.ByteOrder = binary.BigEndian
		var name string
		for ad.Next() {
			switch ad.Type() {
			case unix.NFTA_EXPR_NAME:
				name = ad.String()
				if name == "notrack" {
					e := &expr.Notrack{}
					exprs = append(exprs, e)
				}
			case unix.NFTA_EXPR_DATA:
				var e expr.Any
				switch name {
				case "ct":
					e = &expr.Ct{}
				case "range":
					e = &expr.Range{}
				case "meta":
					e = &expr.Meta{}
				case "cmp":
					e = &expr.Cmp{}
				case "counter":
					e = &expr.Counter{}
				case "objref":
					e = &expr.Objref{}
				case "payload":
					e = &expr.Payload{}
				case "lookup":
					e = &expr.Lookup{}
				case "immediate":
					e = &expr.Immediate{}
				case "bitwise":
					e = &expr.Bitwise{}
				case "redir":
					e = &expr.Redir{}
				case "nat":
					e = &expr.NAT{}
				case "limit":
					e = &expr.Limit{}
				case "quota":
					e = &expr.Quota{}
				case "dynset":
					e = &expr.Dynset{}
				case "log":
					e = &expr.Log{}
				case "exthdr":
					e = &expr.Exthdr{}
				case "match":
					e = &expr.Match{}
				case "target":
					e = &expr.Target{}
				case "connlimit":
					e = &expr.Connlimit{}
				case "queue":
					e = &expr.Queue{}
				case "flow_offload":
					e = &expr.FlowOffload{}
				case "reject":
					e = &expr.Reject{}
				case "masq":
					e = &expr.Masq{}
				case "hash":
					e = &expr.Hash{}
				case "ndpi":
					e = &expr.Ndpi{}
				}
				if e == nil {
					// TODO: introduce an opaque expression type so that users know
					// something is here.
					continue // unsupported expression type
				}

				ad.Do(func(b []byte) error {
					if err := expr.Unmarshal(fam, b, e); err != nil {
						return err
					}
					// Verdict expressions are a special-case of immediate expressions, so
					// if the expression is an immediate writing nothing into the verdict
					// register (invalid), re-parse it as a verdict expression.
					if imm, isImmediate := e.(*expr.Immediate); isImmediate && imm.Register == unix.NFT_REG_VERDICT && len(imm.Data) == 0 {
						e = &expr.Verdict{}
						if err := expr.Unmarshal(fam, b, e); err != nil {
							return err
						}
					}
					exprs = append(exprs, e)
					return nil
				})
			}
		}
		return ad.Err()
	})
	return exprs, ad.Err()
}
