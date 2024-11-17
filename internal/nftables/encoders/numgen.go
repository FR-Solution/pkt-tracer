package encoders

import (
	"fmt"
	"strings"

	"github.com/wildberries-tech/pkt-tracer/internal/nftables/cache"

	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type ExprNumgen struct {
	*nfte.Numgen
	reg Register
}

func newNumgenEncoder(expr *nfte.Numgen, reg Register) *ExprNumgen {
	return &ExprNumgen{Numgen: expr, reg: reg}
}

func (n *ExprNumgen) Mode() string {
	switch n.Type {
	case unix.NFT_NG_INCREMENTAL:
		return "inc"
	case unix.NFT_NG_RANDOM:
		return "random"
	}

	return "unknown"
}

func (expr *ExprNumgen) String() (string, error) {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("numgen %s mod %d", expr.Mode(), expr.Modulus))
	if expr.Offset != 0 {
		sb.WriteString(fmt.Sprintf(" offset %d", expr.Offset))
	}
	if expr.Register == 0 {
		return "", errors.Errorf("%T expression has invalid destination register %d", expr.Numgen, expr.Register)
	}
	expr.reg.InsertExpr(expr.Register,
		cache.RegEntry{
			ExprStr: sb.String(),
			Expr:    expr.Numgen,
		})
	return "", nil
}

func (expr *ExprNumgen) MarshalJSON() ([]byte, error) {
	n := map[string]interface{}{
		"numgen": struct {
			Mode   string `json:"mode"`
			Mod    uint32 `json:"mod"`
			Offset uint32 `json:"offset"`
		}{
			Mode:   expr.Mode(),
			Mod:    expr.Modulus,
			Offset: expr.Offset,
		},
	}
	if expr.Register == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", *expr, expr.Register)
	}
	expr.reg.InsertExpr(expr.Register, cache.RegEntry{Any: n})
	return []byte("{}"), nil
}
