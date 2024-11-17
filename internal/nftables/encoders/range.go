package encoders

import (
	"fmt"
	"strings"

	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

type ExprRange struct {
	*nfte.Range
	reg Register
}

func newRangeEncoder(expr *nfte.Range, reg Register) *ExprRange {
	return &ExprRange{Range: expr, reg: reg}
}

func (expr *ExprRange) String() (string, error) {
	sb := strings.Builder{}
	srcReg, ok := expr.reg.GetExpr(expr.Register)
	if !ok {
		return "", errors.Errorf("%T sexpression has no left hand side", expr.Range)
	}
	left := srcReg.ExprStr

	sb.WriteString(left)
	op := CmpOp(expr.Op).String()
	if op != "" && expr.Op != nfte.CmpOpEq {
		sb.WriteString(fmt.Sprintf(" %s ", op))
	} else {
		sb.WriteByte(' ')
	}
	sb.WriteString(fmt.Sprintf("%s-%s", RawBytes(expr.FromData).String(), RawBytes(expr.ToData).String()))
	return sb.String(), nil
}

func (expr *ExprRange) MarshalJSON() ([]byte, error) {
	srcReg, ok := expr.reg.GetExpr(expr.Register)
	if !ok || srcReg.Any == nil {
		return nil, errors.Errorf("%T sexpression has no left hand side", expr.Range)
	}
	op := CmpOp(expr.Op).String()
	if op == "" {
		op = "in"
	}
	match := map[string]interface{}{
		"match": struct {
			Op    string `json:"op"`
			Left  any    `json:"left"`
			Right any    `json:"right"`
		}{
			Op:   op,
			Left: srcReg.Any,
			Right: map[string]interface{}{
				"range": [2]RawBytes{RawBytes(expr.FromData), RawBytes(expr.ToData)},
			},
		},
	}
	return EncodeJSON(match, false)
}
