package encoders

import (
	"fmt"
	"strings"

	"github.com/wildberries-tech/pkt-tracer/internal/nftables/cache"

	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

type SocketKey nfte.SocketKey

func (s SocketKey) String() string {
	switch nfte.SocketKey(s) {
	case nfte.SocketKeyTransparent:
		return "transparent"
	case nfte.SocketKeyMark:
		return "mark"
	case nfte.SocketKeyWildcard:
		return "wildcard"
	case nfte.SocketKeyCgroupv2:
		return "cgroupv2"
	}
	return "unknown"
}

type ExprSocket struct {
	*nfte.Socket
	reg Register
}

func newSocketEncoder(expr *nfte.Socket, reg Register) *ExprSocket {
	return &ExprSocket{Socket: expr, reg: reg}
}

func (expr *ExprSocket) String() (string, error) {
	sb := strings.Builder{}
	if expr.Register == 0 {
		return "", errors.Errorf("%T expression has invalid destination register %d", expr.Socket, expr.Register)
	}
	sb.WriteString(fmt.Sprintf("socket %s", SocketKey(expr.Key)))
	if expr.Key == nfte.SocketKeyCgroupv2 {
		sb.WriteString(fmt.Sprintf(" level %d", expr.Level))
	}
	expr.reg.InsertExpr(expr.Register, cache.RegEntry{ExprStr: sb.String(), Expr: expr.Socket})
	return "", nil
}

func (expr *ExprSocket) MarshalJSON() ([]byte, error) {
	if expr.Register == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", expr.Socket, expr.Register)
	}
	sock := map[string]interface{}{
		"socket": struct {
			Key string `json:"omitempty"`
		}{
			SocketKey(expr.Key).String(),
		},
	}
	expr.reg.InsertExpr(expr.Register, cache.RegEntry{Any: sock})
	return []byte("{}"), nil
}
