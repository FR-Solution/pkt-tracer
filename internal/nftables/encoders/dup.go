package encoders

import (
	"encoding/json"
	"fmt"
	"strings"

	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

type ExprDup struct {
	*nfte.Dup
	reg Register
}

func newDupEncoder(expr *nfte.Dup, reg Register) *ExprDup {
	return &ExprDup{Dup: expr, reg: reg}
}

func (expr *ExprDup) String() (string, error) {
	var addr, dev string
	sb := strings.Builder{}
	sb.WriteString("dup")
	if expr.RegAddr != 0 {
		srcRegAddr, ok := expr.reg.GetExpr(expr.RegAddr)
		if !ok {
			return "", errors.Errorf("%T statement has no destination expression", expr.Dup)
		}

		addr = srcRegAddr.ExprStr

		if addr != "" {
			sb.WriteString(fmt.Sprintf(" to %s", addr))
		}
	}
	if expr.RegDev != 0 {
		srcRegDev, ok := expr.reg.GetExpr(expr.RegDev)
		if !ok {
			return "", errors.Errorf("%T statement has no destination expression", expr.Dup)
		}
		dev = srcRegDev.ExprStr

		if addr != "" && dev != "" {
			sb.WriteString(fmt.Sprintf(" device %s", dev))
		}
	}
	return sb.String(), nil
}

func (expr *ExprDup) MarshalJSON() ([]byte, error) {
	var addr, dev any
	if expr.RegAddr != 0 {
		srcRegAddr, ok := expr.reg.GetExpr(expr.RegAddr)
		if !ok || srcRegAddr.Any == nil {
			return nil, errors.Errorf("%T statement has no destination expression", expr.Dup)
		}
		addr = srcRegAddr.Any
	}
	if expr.RegDev != 0 {
		srcRegDev, ok := expr.reg.GetExpr(expr.RegDev)
		if !ok || srcRegDev.Any == nil {
			return nil, errors.Errorf("%T statement has no destination expression", expr.Dup)
		}
		dev = srcRegDev.Any
	}

	dup := map[string]interface{}{
		"dup": struct {
			RegAddr any `json:"addr,omitempty"`
			RegDev  any `json:"dev,omitempty"`
		}{
			RegAddr: addr,
			RegDev:  dev,
		},
	}
	return json.Marshal(dup)
}
