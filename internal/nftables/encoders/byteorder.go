package encoders

import (
	"github.com/wildberries-tech/pkt-tracer/internal/nftables/cache"

	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type (
	ByteorderOp nfte.ByteorderOp

	ExprByteorder struct {
		*nfte.Byteorder
		reg Register
	}
)

func (b ByteorderOp) String() string {
	switch nfte.ByteorderOp(b) {
	case nfte.ByteorderNtoh:
		return "ntoh"
	case nfte.ByteorderHton:
		return "hton"
	}
	return ""
}

func newByteorderEncoder(expr *nfte.Byteorder, reg Register) *ExprByteorder {
	return &ExprByteorder{Byteorder: expr, reg: reg}
}

func (expr *ExprByteorder) String() (string, error) {
	srcReg, ok := expr.reg.GetExpr(expr.SourceRegister)
	if !ok {
		return "", errors.Errorf("%T expression has no left hand side", expr.Byteorder)
	}

	op := ByteorderOp(expr.Op).String()
	if op == "" {
		return "", errors.Errorf("invalid byteorder operation: %d", expr.Op)
	}

	if expr.DestRegister == unix.NFT_REG_VERDICT {
		return "", errors.Errorf("invalid destination register %d", expr.DestRegister)
	}

	expr.reg.InsertExpr(expr.DestRegister, cache.RegEntry{
		ExprStr: srcReg.ExprStr,
		Expr:    expr.Byteorder,
		Len:     srcReg.Len,
		Op:      op,
	})
	return "", nil
}

func (expr *ExprByteorder) MarshalJSON() ([]byte, error) {
	srcReg, ok := expr.reg.GetExpr(expr.SourceRegister)
	if !ok {
		return nil, errors.Errorf("%T expression has no left hand side", expr.Byteorder)
	}

	op := ByteorderOp(expr.Op).String()
	if op == "" {
		return nil, errors.Errorf("invalid byteorder operation: %d", expr.Op)
	}

	if expr.DestRegister == unix.NFT_REG_VERDICT {
		return nil, errors.Errorf("invalid destination register %d", expr.DestRegister)
	}

	expr.reg.InsertExpr(expr.DestRegister, cache.RegEntry{
		Expr: srcReg.Expr,
		Any:  srcReg.Any,
		Len:  srcReg.Len,
		Op:   op,
	})

	return []byte("{}"), nil
}
