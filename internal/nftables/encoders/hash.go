package encoders

import (
	"fmt"
	"strings"

	"github.com/wildberries-tech/pkt-tracer/internal/nftables/cache"

	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

type HashType nfte.HashType

func (h HashType) String() string {
	if h == HashType(nfte.HashTypeSym) {
		return "symhash"
	}
	return "jhash"
}

type ExprHash struct {
	*nfte.Hash
	reg Register
}

func newHashEncoder(expr *nfte.Hash, reg Register) *ExprHash {
	return &ExprHash{Hash: expr, reg: reg}
}

func (expr *ExprHash) String() (string, error) {
	sb := strings.Builder{}
	var exp string
	sb.WriteString("symhash")
	if expr.Type != nfte.HashTypeSym {
		srcReg, ok := expr.reg.GetExpr(expr.SourceRegister)
		if !ok {
			return "", errors.Errorf("%T statement has no expression", expr.Hash)
		}
		exp = srcReg.ExprStr

		sb.WriteString(fmt.Sprintf("jhash %s", exp))
	}
	sb.WriteString(fmt.Sprintf(" mod %d seed 0x%x", expr.Modulus, expr.Seed))
	if expr.Offset > 0 {
		sb.WriteString(fmt.Sprintf(" offset %d", expr.Offset))
	}

	if expr.DestRegister == 0 {
		return "", errors.Errorf("%T expression has invalid destination register %d", expr.Hash, expr.DestRegister)
	}

	expr.reg.InsertExpr(expr.DestRegister,
		cache.RegEntry{
			Expr:    expr.Hash,
			ExprStr: sb.String(),
		})

	return "", nil
}

func (expr *ExprHash) MarshalJSON() ([]byte, error) {
	var exp any
	if expr.Type != nfte.HashTypeSym {
		srcReg, ok := expr.reg.GetExpr(expr.SourceRegister)
		if !ok || srcReg.Any == nil {
			return nil, errors.Errorf("%T statement has no expression", expr.Hash)
		}
		exp = srcReg.Any
	}

	hash := map[string]interface{}{
		HashType(expr.Type).String(): struct {
			Mod    uint32 `json:"mod,omitempty"`
			Seed   uint32 `json:"seed,omitempty"`
			Offset uint32 `json:"offset,omitempty"`
			Expr   any    `json:"expr,omitempty"`
		}{
			Mod:    expr.Modulus,
			Seed:   expr.Seed,
			Offset: expr.Offset,
			Expr:   exp,
		},
	}

	if expr.DestRegister == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", expr.Hash, expr.DestRegister)
	}

	expr.reg.InsertExpr(expr.DestRegister,
		cache.RegEntry{
			Any: hash,
		})
	return []byte("{}"), nil
}
