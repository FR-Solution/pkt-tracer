package encoders

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/wildberries-tech/pkt-tracer/internal/nftables/cache"

	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const (
	LogicAND LogicOp = iota
	LogicOR
	LogicXOR
	LogicLShift
	LogicRShift
)

type (
	LogicOp    uint32
	BitwiseOps uint32
)

func (l LogicOp) String() string {
	switch l {
	case LogicAND:
		return "&"
	case LogicOR:
		return "|"
	case LogicXOR:
		return "^"
	case LogicLShift:
		return "<<"
	case LogicRShift:
		return ">>"
	}
	return ""
}

func scan0(x *big.Int, start int) int {
	for i := start; i < x.BitLen(); i++ {
		if x.Bit(i) == 0 {
			return i
		}
	}
	return -1
}

type ExprBitwise struct {
	*nfte.Bitwise
	reg     Register
	hdrDesc *ProtoDescPtr
	mask    *big.Int
	xor     *big.Int
	o       *big.Int
}

func newBitwiseEncoder(expr *nfte.Bitwise, reg Register, hdrDesc *ProtoDescPtr) *ExprBitwise {
	return &ExprBitwise{Bitwise: expr, reg: reg, hdrDesc: hdrDesc}
}

func (expr *ExprBitwise) bitwiseEval() {
	expr.mask = new(big.Int).SetBytes(expr.Mask)
	expr.xor = new(big.Int).SetBytes(expr.Xor)
	expr.o = big.NewInt(0)

	if scan0(expr.mask, 0) != int(expr.Len) || expr.xor.Uint64() != 0 {
		/* o = (m & x) ^ x */
		expr.o = new(big.Int).And(expr.mask, expr.xor)
		expr.o = new(big.Int).Xor(expr.o, expr.xor)
		expr.xor = new(big.Int).And(expr.xor, expr.mask)
		expr.mask = new(big.Int).Or(expr.mask, expr.o)
	}
}

func (expr *ExprBitwise) String() (string, error) {
	const hexBase = 16
	containExpression := func(s string) bool {
		re := regexp.MustCompile(`[()&|^<> ]`)
		return re.MatchString(s)
	}
	sb := strings.Builder{}
	srcReg, ok := expr.reg.GetExpr(expr.SourceRegister)
	if !ok {
		return "", errors.Errorf("%T expression has no left side", expr.Bitwise)
	}

	if expr.DestRegister == unix.NFT_REG_VERDICT {
		return "", errors.Errorf("%T expression has invalid destination register %d", expr.Bitwise, expr.DestRegister)
	}
	expr.bitwiseEval()

	exp := srcReg.ExprStr

	switch t := srcReg.Expr.(type) {
	case *nfte.Ct:
		exp = fmt.Sprintf("%s %s", exp, CtDesk[t.Key](expr.Mask))
		expr.reg.InsertExpr(expr.DestRegister, cache.RegEntry{
			ExprStr: exp,
			Expr:    expr.Bitwise,
		})
		return "", nil
	case *nfte.Payload:
		offset := HeaderOffset(t.Offset).BytesToBits().WithBitMask(uint32(RawBytes(expr.Mask).Uint64())) //nolint:gosec
		hdrDesc := *expr.hdrDesc
		defer func() { *expr.hdrDesc = hdrDesc }()
		if hdrDesc != nil {
			if desc, ok := hdrDesc.Offsets[offset]; ok {
				exp = fmt.Sprintf("%s %s", hdrDesc.Name, desc.Name)
				hdrDesc.CurrentOffset = offset
			}
		} else if proto, ok := Protocols[t.Base]; ok && t.Base == nfte.PayloadBaseNetworkHeader {
			header := proto[unix.IPPROTO_IP]
			if desc, ok := header.Offsets[offset]; ok {
				exp = fmt.Sprintf("%s %s", header.Name, desc.Name)
				hdrDesc = &header
				hdrDesc.CurrentOffset = offset
			}
		}
		expr.reg.InsertExpr(expr.DestRegister, cache.RegEntry{
			ExprStr: exp,
			Expr:    expr.Bitwise,
		})
		return "", nil
	}

	if !(srcReg.Len > 0 && scan0(expr.mask, 0) >= int(srcReg.Len)) {
		if containExpression(exp) {
			sb.WriteString(fmt.Sprintf("((%s) %s %s)", exp, LogicAND.String(), expr.mask.Text(hexBase)))
		} else {
			sb.WriteString(fmt.Sprintf("(%s %s %s)", exp, LogicAND.String(), expr.mask.Text(hexBase)))
		}
		exp = sb.String()
		sb.Reset()
	}

	if expr.xor.Uint64() != 0 {
		if containExpression(exp) {
			sb.WriteString(fmt.Sprintf("((%s) %s %s)", exp, LogicXOR.String(), expr.xor.Text(hexBase)))
		} else {
			sb.WriteString(fmt.Sprintf("(%s %s %s)", exp, LogicXOR.String(), expr.xor.Text(hexBase)))
		}
		exp = sb.String()
		sb.Reset()
	}

	if expr.o.Uint64() != 0 {
		if containExpression(exp) {
			sb.WriteString(fmt.Sprintf("((%s) %s %s)", exp, LogicOR.String(), expr.o.Text(hexBase)))
		} else {
			sb.WriteString(fmt.Sprintf("(%s %s %s)", exp, LogicOR.String(), expr.o.Text(hexBase)))
		}
		exp = sb.String()
		sb.Reset()
	}

	expr.reg.InsertExpr(expr.DestRegister, cache.RegEntry{
		ExprStr: exp,
		Len:     srcReg.Len,
		Expr:    expr.Bitwise,
	})

	return "", nil
}

func (expr *ExprBitwise) MarshalJSON() ([]byte, error) {
	type exprCmp struct {
		Op    string `json:"op"`
		Left  any    `json:"left"`
		Right any    `json:"right"`
	}

	srcReg, ok := expr.reg.GetExpr(expr.SourceRegister)
	if !ok {
		return nil, errors.Errorf("%T expression has no left side", expr.Bitwise)
	}

	if expr.DestRegister == unix.NFT_REG_VERDICT {
		return nil, errors.Errorf("%T expression has invalid destination register %d", expr.Bitwise, expr.DestRegister)
	}

	expr.bitwiseEval()

	exp := srcReg.Any

	if !(srcReg.Len > 0 && scan0(expr.mask, 0) >= int(srcReg.Len)) {
		exp = exprCmp{
			Op:    LogicAND.String(),
			Left:  exp,
			Right: expr.mask.Uint64(),
		}
	}

	if expr.xor.Uint64() != 0 {
		exp = exprCmp{
			Op:    LogicXOR.String(),
			Left:  exp,
			Right: expr.xor.Uint64(),
		}
	}

	if expr.o.Uint64() != 0 {
		exp = exprCmp{
			Op:    LogicOR.String(),
			Left:  exp,
			Right: expr.o.Uint64(),
		}
	}

	expr.reg.InsertExpr(expr.DestRegister, cache.RegEntry{
		Any: exp,
		Len: srcReg.Len,
	})

	return []byte("{}"), nil
}
