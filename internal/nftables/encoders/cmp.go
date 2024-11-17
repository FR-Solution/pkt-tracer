package encoders

import (
	"bytes"
	"fmt"
	"strings"

	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type CmpOp nfte.CmpOp

func (c CmpOp) String() string {
	switch nfte.CmpOp(c) {
	case nfte.CmpOpEq:
		return "=="
	case nfte.CmpOpNeq:
		return "!="
	case nfte.CmpOpLt:
		return "<"
	case nfte.CmpOpLte:
		return "<="
	case nfte.CmpOpGt:
		return ">"
	case nfte.CmpOpGte:
		return ">="
	}
	return ""
}

type ExprCmp struct {
	*nfte.Cmp
	reg     Register
	hdrDesc *ProtoDescPtr
}

func (expr *ExprCmp) AddProto(p int) {

}

func newCmpEncoder(expr *nfte.Cmp, reg Register, hdrDesc *ProtoDescPtr) *ExprCmp {
	return &ExprCmp{Cmp: expr, reg: reg, hdrDesc: hdrDesc}
}

func (expr *ExprCmp) String() (string, error) {
	sb := strings.Builder{}

	srcReg, ok := expr.reg.GetExpr(expr.Register)
	if !ok {
		return "", errors.Errorf("%T expression has no left hand side", expr.Cmp)
	}
	left := srcReg.ExprStr

	var right string
	switch t := srcReg.Expr.(type) {
	case *nfte.Meta:
		var protos ProtoTypeHolder
		switch t.Key {
		case nfte.MetaKeyL4PROTO, nfte.MetaKeyPROTOCOL:
			protos = Protocols[nfte.PayloadBaseTransportHeader]
		case nfte.MetaKeyNFPROTO:
			protos = Protocols[nfte.PayloadBaseNetworkHeader]
		default:
			if metaExpr, ok := srcReg.Any.(*ExprMeta); ok {
				right = metaExpr.metaDataToString(expr.Data)
			}
		}
		if proto, ok := protos[ProtoType(int(RawBytes(expr.Data).Uint64()))]; ok { //nolint:gosec
			right = proto.Name
			*expr.hdrDesc = &proto
		}
	case *nfte.Bitwise:
		if RawBytes(expr.Data).Uint64() != 0 {
			right = fmt.Sprintf("0x%s", RawBytes(expr.Data).Text(baseHex))
		}
		hdrDesc := *expr.hdrDesc
		if hdrDesc != nil {
			if desc, ok := hdrDesc.Offsets[hdrDesc.CurrentOffset]; ok {
				right = desc.Desc(expr.Data)
			}
		}
	case *nfte.Ct:
		right = CtDesk[t.Key](expr.Data)
	case *nfte.Payload:
		hdrDesc := *expr.hdrDesc
		if hdrDesc != nil {
			if desc, ok := hdrDesc.Offsets[hdrDesc.CurrentOffset]; ok {
				right = desc.Desc(expr.Data)
			}
		} else if proto, ok := Protocols[t.Base]; ok && t.Base == nfte.PayloadBaseNetworkHeader {
			header := proto[unix.IPPROTO_IP]
			if desc, ok := header.Offsets[HeaderOffset(t.Offset).BytesToBits()]; ok {
				left = fmt.Sprintf("%s %s", header.Name, desc.Name)
				right = desc.Desc(expr.Data)
			}
		} else if proto, ok := Protocols[t.Base]; ok && t.Base == nfte.PayloadBaseTransportHeader {
			header := proto[unix.IPPROTO_NONE]
			if desc, ok := header.Offsets[HeaderOffset(t.Offset).BytesToBits()]; ok {
				left = fmt.Sprintf("%s %s", header.Name, desc.Name)
				right = desc.Desc(expr.Data)
			}
		}
	default:
		right = RawBytes(expr.Data).Text(baseDec)
	}

	op := CmpOp(expr.Op).String()
	if expr.Op == nfte.CmpOpEq {
		op = ""
	}

	if op != "" && right != "" {
		sb.WriteString(fmt.Sprintf("%s %s %s", left, op, right))
	} else if right != "" {
		sb.WriteString(fmt.Sprintf("%s %s", left, right))
	} else {
		sb.WriteString(left)
	}

	return sb.String(), nil
}

func (expr *ExprCmp) MarshalJSON() ([]byte, error) {
	srcReg, ok := expr.reg.GetExpr(expr.Register)
	if !ok || srcReg.Any == nil {
		return nil, errors.Errorf("%T expression has no left hand side", expr.Cmp)
	}

	var right any
	switch t := srcReg.Expr.(type) {
	case *nfte.Meta:
		switch t.Key {
		case nfte.MetaKeyL4PROTO:
			switch RawBytes(expr.Data).Uint64() {
			case unix.IPPROTO_TCP:
				right = "tcp"
			case unix.IPPROTO_UDP:
				right = "udp"
			default:
				right = "unknown"
			}
		case nfte.MetaKeyIIFNAME, nfte.MetaKeyOIFNAME:
			right = string(bytes.TrimRight(expr.Data, "\x00"))
		case nfte.MetaKeyNFTRACE:
			right = RawBytes(expr.Data).Uint64()
		default:
			right = RawBytes(expr.Data)
		}
	default:
		right = RawBytes(expr.Data)
	}

	cmp := map[string]interface{}{
		"match": struct {
			Op    string `json:"op"`
			Left  any    `json:"left"`
			Right any    `json:"right"`
		}{
			Op:    CmpOp(expr.Op).String(),
			Left:  srcReg.Any,
			Right: right,
		},
	}

	return EncodeJSON(cmp, false)
}
