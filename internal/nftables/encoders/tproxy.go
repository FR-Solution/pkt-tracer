package encoders

import (
	"encoding/json"
	"fmt"
	"strings"

	nfte "github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type (
	Family byte
)

func (t Family) String() string {
	switch t {
	case unix.NFPROTO_IPV4:
		return "ip"
	case unix.NFPROTO_IPV6:
		return "ip6"
	case unix.NFPROTO_INET:
		return "inet"
	case unix.NFPROTO_NETDEV:
		return "netdev"
	case unix.NFPROTO_ARP:
		return "arp"
	case unix.NFPROTO_BRIDGE:
		return "bridge"
	}
	return "unknown"
}

type ExprTProxy struct {
	*nfte.TProxy
	reg Register
}

func newTProxyEncoder(expr *nfte.TProxy, reg Register) *ExprTProxy {
	return &ExprTProxy{TProxy: expr, reg: reg}
}

func (expr *ExprTProxy) String() (string, error) {
	var (
		addr, port string
		sb         = strings.Builder{}
	)
	addrExpr, _ := expr.reg.GetExpr(expr.RegAddr)
	portExpr, _ := expr.reg.GetExpr(expr.RegPort)

	addr = addrExpr.ExprStr
	port = portExpr.ExprStr

	sb.WriteString("tproxy")
	if expr.TableFamily == unix.NFPROTO_INET && expr.Family != unix.NFPROTO_UNSPEC {
		sb.WriteString(fmt.Sprintf(" %s", Family(expr.Family)))
	}
	sb.WriteString(" to")
	if addr != "" {
		if expr.Family == unix.NFPROTO_IPV6 {
			if expr.Family == unix.NFPROTO_IPV6 {
				addr = fmt.Sprintf("[%s]", addr)
			}
		}
		sb.WriteString(fmt.Sprintf(" %s", addr))
	}
	if port != "" {
		if addr == " " {
			sb.WriteByte(' ')
		}
		sb.WriteString(fmt.Sprintf(":%s", port))
	}
	return sb.String(), nil
}

func (expr *ExprTProxy) MarshalJSON() ([]byte, error) {
	addrExpr, _ := expr.reg.GetExpr(expr.RegAddr)
	portExpr, _ := expr.reg.GetExpr(expr.RegPort)
	root := struct {
		Family string `json:"op,omitempty"`
		Addr   any    `json:"addr,omitempty"`
		Port   any    `json:"port,omitempty"`
	}{
		Addr: addrExpr.Any,
		Port: portExpr.Any,
	}
	if expr.TableFamily == unix.NFPROTO_INET && expr.Family != unix.NFPROTO_UNSPEC {
		root.Family = Family(expr.Family).String()
	}
	tproxy := map[string]interface{}{
		"tproxy": root,
	}

	return json.Marshal(tproxy)
}
