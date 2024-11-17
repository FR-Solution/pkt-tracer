package encoders

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/nftables"
	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type DynSetOP uint32

const (
	DynSetOPAdd    DynSetOP = unix.NFT_DYNSET_OP_ADD
	DynSetOPUpdate DynSetOP = unix.NFT_DYNSET_OP_UPDATE
	DynSetOPDelete DynSetOP = iota
)

func (d DynSetOP) String() string {
	switch d {
	case DynSetOPAdd:
		return "add"
	case DynSetOPUpdate:
		return "update"
	case DynSetOPDelete:
		return "delete"
	}
	return "unknown"
}

type ExprDynset struct {
	*nfte.Dynset
	reg   Register
	table *nftables.Table
}

func newDynsetEncoder(expr *nfte.Dynset, reg Register) *ExprDynset {
	return &ExprDynset{Dynset: expr, reg: reg}
}

func (expr *ExprDynset) String() (string, error) {
	sb := strings.Builder{}
	srcRegKey, ok := expr.reg.GetExpr(expr.SrcRegKey)
	if !ok {
		return "", errors.Errorf("%T statement has no key expression", expr.Dynset)
	}
	exp := srcRegKey.ExprStr

	sb.WriteString(exp)
	str, err := newRuleExprs(expr.Exprs, expr.table, expr.reg).String()
	if err != nil {
		return "", err
	}
	if str != "" {
		sb.WriteByte(' ')
		sb.WriteString(str)
	}

	if expr.Timeout != 0 {
		sb.WriteString(fmt.Sprintf(" timeout %s", expr.Timeout))
	}

	if sb.Len() > 0 {
		exp = sb.String()
	}
	sb.Reset()
	setName := fmt.Sprintf(`@%s`, expr.SetName)

	sb.WriteString(fmt.Sprintf("%s %s { %s ", DynSetOP(expr.Operation), setName, exp))
	if str != "" {
		sb.WriteString(str)
		sb.WriteByte(' ')
	}

	srcRegData, ok := expr.reg.GetExpr(expr.SrcRegData)

	if ok {
		if exprData := srcRegData.ExprStr; exprData != "" {
			sb.WriteString(fmt.Sprintf(": %s ", exprData))
		}
	}

	sb.WriteByte('}')

	return sb.String(), nil
}

func (expr *ExprDynset) MarshalJSON() ([]byte, error) {
	srcRegKey, ok := expr.reg.GetExpr(expr.SrcRegKey)
	if !ok || srcRegKey.Any == nil {
		return nil, errors.Errorf("%T statement has no key expression", expr.Dynset)
	}
	exp := srcRegKey.Any
	if expr.Timeout != 0 {
		exp = map[string]interface{}{
			"elem": struct {
				Val     any           `val:"json"`
				Timeout time.Duration `timeout:"json"`
			}{
				Val:     exp,
				Timeout: expr.Timeout,
			},
		}
	}
	setName := fmt.Sprintf(`@%s`, expr.SetName)
	srcRegData, ok := expr.reg.GetExpr(expr.SrcRegData)

	if ok && srcRegData.Any != nil {
		exp = map[string]interface{}{
			"map": struct {
				Op   string `json:"op"`
				Elem any    `json:"elem"`
				Data any    `json:"data"`
				Map  string `json:"map"`
			}{
				Op:   DynSetOP(expr.Operation).String(),
				Elem: exp,
				Data: srcRegData.Any,
				Map:  setName,
			},
		}
		return EncodeJSON(exp, false)
	}
	exp = map[string]interface{}{
		"set": struct {
			Op   string     `json:"op"`
			Elem any        `json:"elem"`
			Set  string     `json:"set"`
			Stmt []nfte.Any `json:"stmt,omitempty"`
		}{
			Op:   DynSetOP(expr.Operation).String(),
			Elem: exp,
			Set:  setName,
			Stmt: expr.Exprs,
		},
	}
	return EncodeJSON(exp, false)
}
