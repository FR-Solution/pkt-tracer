package parser

import (
	"encoding/binary"

	nfte "github.com/wildberries-tech/pkt-tracer/internal/nftables/encoders"

	nftLib "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type Rule nftLib.Rule

func (r *Rule) InitFromMsg(msg netlink.Message) error {
	fam := nftLib.TableFamily(msg.Data[0])
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_RULE_TABLE:
			r.Table = &nftLib.Table{
				Name:   ad.String(),
				Family: fam,
			}
		case unix.NFTA_RULE_CHAIN:
			r.Chain = &nftLib.Chain{Name: ad.String()}
		case unix.NFTA_RULE_EXPRESSIONS:
			ad.Do(func(b []byte) error {
				exprs, err := ParseExprMsgFunc(byte(fam), b)
				if err != nil {
					return err
				}
				r.Exprs = make([]expr.Any, len(exprs))
				for i := range exprs {
					r.Exprs[i] = exprs[i].(expr.Any)
				}
				return nil
			})
		case unix.NFTA_RULE_POSITION:
			r.Position = ad.Uint64()
		case unix.NFTA_RULE_HANDLE:
			r.Handle = ad.Uint64()
		case unix.NFTA_RULE_USERDATA:
			r.UserData = ad.Bytes()
		}
	}
	return ad.Err()
}

// JsonString - represent rule expressions as string json
func (r *Rule) JsonString() (string, error) {
	b, err := nfte.EncodeJSON((*nfte.RuleEncode)(r), false)
	return string(b), err
}

// String - represent rule expressions as a string
func (r *Rule) String() (string, error) {
	if r == nil {
		return "", errors.Errorf("%T type must be implement", r)
	}
	return (*nfte.RuleEncode)(r).String()
}
