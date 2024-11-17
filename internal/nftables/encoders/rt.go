package encoders

import (
	"fmt"

	"github.com/wildberries-tech/pkt-tracer/internal/nftables/cache"

	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

type RtKey nfte.RtKey

func (r RtKey) String() string {
	switch nfte.RtKey(r) {
	case nfte.RtClassid:
		return "classid"
	case nfte.RtNexthop4:
		return "nexthop"
	case nfte.RtNexthop6:
		return "nexthop"
	case nfte.RtTCPMSS:
		return "mtu"
	}
	return "unknown"
}

func (r RtKey) Family() string {
	switch nfte.RtKey(r) {
	case nfte.RtNexthop4:
		return "ip"
	case nfte.RtNexthop6:
		return "ip6"
	}
	return ""
}

type ExprRt struct {
	*nfte.Rt
	reg Register
}

func newRtEncoder(expr *nfte.Rt, reg Register) *ExprRt {
	return &ExprRt{Rt: expr, reg: reg}
}

func (expr *ExprRt) String() (string, error) {
	if expr.Register == 0 {
		return "", errors.Errorf("%T expression has invalid destination register %d", expr.Rt, expr.Register)
	}
	expr.reg.InsertExpr(expr.Register,
		cache.RegEntry{
			ExprStr: fmt.Sprintf("rt %s %s", RtKey(expr.Key).Family(), RtKey(expr.Key)),
		},
	)
	return "", nil
}

func (expr *ExprRt) MarshalJSON() ([]byte, error) {
	rt := map[string]interface{}{
		"rt": struct {
			Key    string `json:"key"`
			Family string `json:"family,omitempty"`
		}{
			Key:    RtKey(expr.Key).String(),
			Family: RtKey(expr.Key).Family(),
		},
	}

	if expr.Register == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", expr.Rt, expr.Register)
	}
	expr.reg.InsertExpr(expr.Register, cache.RegEntry{Any: rt})
	return []byte("{}"), nil
}
