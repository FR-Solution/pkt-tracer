package encoders

import (
	"fmt"
	"strings"

	"github.com/wildberries-tech/pkt-tracer/internal/nftables/cache"

	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

type ExprFib struct {
	*nfte.Fib
	reg Register
}

func newFibEncoder(expr *nfte.Fib, reg Register) *ExprFib {
	return &ExprFib{Fib: expr, reg: reg}
}

func (f *ExprFib) ResultString() string {
	if f.ResultOIF {
		return "oif"
	}
	if f.ResultOIFNAME {
		return "oifname"
	}
	if f.ResultADDRTYPE {
		return "type"
	}
	return "unknown"
}

func (f *ExprFib) FlagsString() (flags []string) {
	if f.FlagSADDR {
		flags = append(flags, "saddr")
	}
	if f.FlagDADDR {
		flags = append(flags, "daddr")
	}
	if f.FlagMARK {
		flags = append(flags, "mark")
	}
	if f.FlagIIF {
		flags = append(flags, "iif")
	}
	if f.FlagOIF {
		flags = append(flags, "oif")
	}
	return flags
}

func (expr *ExprFib) String() (string, error) {
	if expr.Register == 0 {
		return "", errors.Errorf("%T expression has invalid destination register %d", expr.Fib, expr.Register)
	}
	expr.reg.InsertExpr(expr.Register,
		cache.RegEntry{
			ExprStr: fmt.Sprintf("fib %s %s", strings.Join(expr.FlagsString(), ", "), expr.ResultString()),
			Expr:    expr.Fib,
		})
	return "", nil
}

func (expr *ExprFib) MarshalJSON() ([]byte, error) {
	fib := map[string]interface{}{
		"fib": struct {
			Result string   `json:"result"`
			Flags  []string `json:"flags"`
		}{
			Result: expr.ResultString(),
			Flags:  expr.FlagsString(),
		},
	}
	if expr.Register == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", expr.Fib, expr.Register)
	}
	expr.reg.InsertExpr(expr.Register, cache.RegEntry{Any: fib})
	return []byte("{}"), nil
}
