package encoders

import (
	"encoding/json"
	"fmt"

	"github.com/wildberries-tech/pkt-tracer/internal/nftables/cache"

	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type (
	PayloadOperationType nfte.PayloadOperationType
	PayloadBase          nfte.PayloadBase
)

func (p PayloadOperationType) String() string {
	switch nfte.PayloadOperationType(p) {
	case nfte.PayloadLoad:
		return "load"
	case nfte.PayloadWrite:
		return "write"
	}
	return ""
}

func (p PayloadBase) String() string {
	switch nfte.PayloadBase(p) {
	case nfte.PayloadBaseLLHeader:
		return "ll"
	case nfte.PayloadBaseNetworkHeader:
		return "nh"

	case nfte.PayloadBaseTransportHeader:
		return "th"
	}
	return ""
}

type ExprPayload struct {
	*nfte.Payload
	reg     Register
	hdrDesc *ProtoDescPtr
}

func newPayloadEncoder(expr *nfte.Payload, reg Register, hdrDesc *ProtoDescPtr) *ExprPayload {
	return &ExprPayload{Payload: expr, reg: reg, hdrDesc: hdrDesc}
}

func (expr *ExprPayload) String() (string, error) {
	pl := fmt.Sprintf("@%s,%d,%d", PayloadBase(expr.Base), expr.Offset, expr.Len)
	offset := HeaderOffset(expr.Offset).BytesToBits()
	hdrDesc := *expr.hdrDesc
	defer func() { *expr.hdrDesc = hdrDesc }()
	if hdrDesc != nil {
		if desc, ok := hdrDesc.Offsets[offset]; ok {
			pl = desc.Name
			hdrDesc.CurrentOffset = offset
		}
	} else if proto, ok := Protocols[expr.Base]; ok {
		if expr.Base == nfte.PayloadBaseNetworkHeader {
			header := proto[unix.IPPROTO_IP]

			if desc, ok := header.Offsets[offset]; ok {
				pl = fmt.Sprintf("%s %s", header.Name, desc.Name)
				hdrDesc = &header
				hdrDesc.CurrentOffset = offset
			}
		}
	}

	if expr.DestRegister != 0 {
		expr.reg.InsertExpr(expr.DestRegister,
			cache.RegEntry{
				ExprStr: pl,
				Expr:    expr.Payload,
			})
		return "", nil
	}
	srcReg, ok := expr.reg.GetExpr(expr.SourceRegister)

	if !ok {
		return "", errors.Errorf("%T statement has no expression", expr.Payload)
	}
	val := srcReg.ExprStr

	return fmt.Sprintf("%s set %s", pl, val), nil
}

func (expr *ExprPayload) MarshalJSON() ([]byte, error) {
	pl := map[string]interface{}{
		"payload": struct {
			Base   string `json:"base"`
			Offset uint32 `json:"offset"`
			Len    uint32 `json:"len"`
		}{
			Base:   PayloadBase(expr.Base).String(),
			Offset: expr.Offset,
			Len:    expr.Len,
		},
	}

	if expr.DestRegister != 0 {
		expr.reg.InsertExpr(expr.DestRegister, cache.RegEntry{Any: pl, Expr: expr.Payload})
		return []byte("{}"), nil
	}

	srcReg, ok := expr.reg.GetExpr(expr.SourceRegister)

	if !ok || srcReg.Any == nil {
		return nil, errors.Errorf("%T statement has no expression", expr.Payload)
	}

	mangle := map[string]interface{}{
		"mangle": struct {
			Key any `json:"key"`
			Val any `json:"value"`
		}{
			Key: pl,
			Val: srcReg.Any,
		},
	}
	return json.Marshal(mangle)
}
