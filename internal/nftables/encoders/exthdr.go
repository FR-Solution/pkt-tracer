package encoders

import (
	"encoding/json"
	"fmt"

	"github.com/wildberries-tech/pkt-tracer/internal/nftables/cache"

	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type ExprExthdr struct {
	*nfte.Exthdr
	reg Register
}

func newExthdrEncoder(expr *nfte.Exthdr, reg Register) *ExprExthdr {
	return &ExprExthdr{Exthdr: expr, reg: reg}
}

func (expr *ExprExthdr) String() (string, error) {
	exp := ""
	op := "exthdr"
	switch expr.Op {
	case nfte.ExthdrOpTcpopt:
		op = "tcp option"
	case nfte.ExthdrOpIpv6:
		op = "ip option"
	}
	if expr.Offset == 0 && expr.Flags == unix.NFT_EXTHDR_F_PRESENT {
		exp = fmt.Sprintf("%s %d", op, expr.Type)
	} else {
		exp = fmt.Sprintf("%s @%d,%d,%d", op, expr.Type, expr.Offset, expr.Len)
	}

	if expr.DestRegister != 0 {
		expr.reg.InsertExpr(expr.DestRegister,
			cache.RegEntry{
				ExprStr: exp,
				Expr:    expr.Exthdr,
			})
		return "", nil
	}

	if expr.SourceRegister != 0 {
		srcReg, ok := expr.reg.GetExpr(expr.SourceRegister)
		if !ok {
			return "", errors.Errorf("%T statement has no expression", expr.Exthdr)
		}
		val := srcReg.ExprStr

		return fmt.Sprintf("%s set %s", exp, val), nil
	}

	return fmt.Sprintf("reset %s", exp), nil
}

func (expr *ExprExthdr) MarshalJSON() ([]byte, error) {
	op := "exthdr"
	switch expr.Op {
	case nfte.ExthdrOpTcpopt:
		op = "tcp option"
	case nfte.ExthdrOpIpv6:
		op = "ip option"
	}

	hdr := map[string]interface{}{
		op: struct {
			Base   uint8  `json:"base"`
			Offset uint32 `json:"offset"`
			Len    uint32 `json:"len"`
		}{
			Base:   expr.Type,
			Offset: expr.Offset,
			Len:    expr.Len,
		},
	}

	if expr.DestRegister != 0 {
		expr.reg.InsertExpr(expr.DestRegister, cache.RegEntry{Any: hdr})
		return []byte("{}"), nil
	}

	if expr.SourceRegister != 0 {
		srcReg, ok := expr.reg.GetExpr(expr.SourceRegister)
		if !ok || srcReg.Any == nil {
			return nil, errors.Errorf("%T statement has no expression", expr.Exthdr)
		}
		mangle := map[string]interface{}{
			"mangle": struct {
				Key any `json:"key"`
				Val any `json:"value"`
			}{
				Key: hdr,
				Val: srcReg.Any,
			},
		}
		return json.Marshal(mangle)
	}

	return json.Marshal(hdr)
}
