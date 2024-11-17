package encoders

import (
	"encoding/json"
	"fmt"
	"strings"

	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const (
	NATTypeMASQ nfte.NATType = iota + unix.NFT_NAT_DNAT + 1
	NATTypeRedir
)

type NATType nfte.NATType

func (n NATType) String() string {
	switch nfte.NATType(n) {
	case nfte.NATTypeSourceNAT:
		return "snat"
	case nfte.NATTypeDestNAT:
		return "dnat"
	case NATTypeMASQ:
		return "masquerade"
	case NATTypeRedir:
		return "redirect"
	}
	return "unknown"
}

type ExprNAT struct {
	*nfte.NAT
	reg Register
}

func newNATEncoder(expr *nfte.NAT, reg Register) *ExprNAT {
	return &ExprNAT{NAT: expr, reg: reg}
}

func (n *ExprNAT) FamilyStr() string {
	switch n.Family {
	case unix.NFPROTO_IPV4:
		return "ip" //nolint:goconst
	case unix.NFPROTO_IPV6:
		return "ip6" //nolint:goconst
	case unix.NFPROTO_INET:
		return "inet"
	case unix.NFPROTO_NETDEV:
		return "netdev"
	case unix.NFPROTO_ARP:
		return "arp"
	case unix.NFPROTO_BRIDGE:
		return "bridge"
	}
	return ""
}

func (n *ExprNAT) Flags() (flags []string) {
	if n.Random {
		flags = append(flags, "random")
	}
	if n.FullyRandom {
		flags = append(flags, "fully-random")
	}
	if n.Persistent {
		flags = append(flags, "persistent")
	}
	return flags
}

func (expr *ExprNAT) String() (string, error) {
	var addr, port string
	sb := strings.Builder{}
	sb.WriteString(NATType(expr.Type).String())
	if expr.RegAddrMin != 0 {
		addrMinExpr, ok := expr.reg.GetExpr(expr.RegAddrMin)
		if !ok {
			return "", errors.Errorf("%T statement has no address expression", expr.NAT)
		}
		addr = addrMinExpr.ExprStr

		if expr.Family == unix.NFPROTO_IPV6 {
			if expr.Family == unix.NFPROTO_IPV6 {
				addr = fmt.Sprintf("[%s]", addr)
			}
		}
	}
	if expr.RegAddrMax != 0 && expr.RegAddrMax != expr.RegAddrMin {
		addrMaxExpr, ok := expr.reg.GetExpr(expr.RegAddrMax)
		if !ok {
			return "", errors.Errorf("%T statement has no address expression", expr.NAT)
		}
		if addr == "" {
			addr = addrMaxExpr.ExprStr
			if expr.Family == unix.NFPROTO_IPV6 {
				if expr.Family == unix.NFPROTO_IPV6 {
					addr = fmt.Sprintf("[%s]", addr)
				}
			}
		} else {
			addrMax := addrMaxExpr.ExprStr
			if addrMax != "" {
				addr = fmt.Sprintf("%s-%s", addr, addrMax)
			}
			if expr.Family == unix.NFPROTO_IPV6 {
				addr = fmt.Sprintf("%s-[%s]", addr, addrMax)
			}
		}
	}
	if expr.RegProtoMin != 0 {
		portMinExpr, ok := expr.reg.GetExpr(expr.RegProtoMin)
		if !ok {
			return "", errors.Errorf("%T statement has no port expression", expr.NAT)
		}
		port = portMinExpr.ExprStr
	}
	if expr.RegProtoMax != 0 && expr.RegProtoMax != expr.RegProtoMin {
		portMaxExpr, ok := expr.reg.GetExpr(expr.RegProtoMax)
		if !ok {
			return "", errors.Errorf("%T statement has no port expression", expr.NAT)
		}
		if port == "" {
			port = portMaxExpr.ExprStr
		} else {
			portMax := portMaxExpr.ExprStr
			if portMax != "" {
				port = fmt.Sprintf("%s-%s", port, portMax)
			}
		}
	}
	if addr != "" || port != "" {
		switch expr.Family {
		case unix.NFPROTO_IPV4:
			sb.WriteString(" ip")
		case unix.NFPROTO_IPV6:
			sb.WriteString(" ip6")
		}
		sb.WriteString(" to")
	}
	if addr != "" {
		sb.WriteString(fmt.Sprintf(" %s", addr))
	}
	if port != "" {
		if addr == "" {
			sb.WriteByte(' ')
		}
		sb.WriteString(fmt.Sprintf(":%s", port))
	}
	flags := expr.Flags()
	if len(flags) > 0 {
		sb.WriteString(fmt.Sprintf(" %s", strings.Join(flags, " ")))
	}
	return sb.String(), nil
}

func (expr *ExprNAT) MarshalJSON() ([]byte, error) {
	var (
		flag       any
		family     string
		addr, port any
	)
	flags := expr.Flags()

	if len(flags) > 1 {
		flag = flags
	} else if len(flags) == 1 {
		flag = flags[0]
	}

	if expr.Family == unix.NFPROTO_IPV4 || expr.Family == unix.NFPROTO_IPV6 {
		family = expr.FamilyStr()
	}
	if expr.RegAddrMin != 0 {
		addrMinExpr, ok := expr.reg.GetExpr(expr.RegAddrMin)
		if !ok {
			return nil, errors.Errorf("%T statement has no address expression", expr.NAT)
		}
		addr = addrMinExpr.Any
	}

	if expr.RegAddrMax != 0 && expr.RegAddrMax != expr.RegAddrMin {
		addrMaxExpr, ok := expr.reg.GetExpr(expr.RegAddrMax)
		if !ok || addrMaxExpr.Any == nil {
			return nil, errors.Errorf("%T statement has no address expression", expr.NAT)
		}
		if addr == nil {
			addr = addrMaxExpr.Any
		} else {
			addr = map[string]interface{}{
				"range": [2]any{addr, addrMaxExpr.Any},
			}
		}
	}

	if expr.RegProtoMin != 0 {
		portMinExpr, ok := expr.reg.GetExpr(expr.RegProtoMin)
		if !ok || portMinExpr.Any == nil {
			return nil, errors.Errorf("%T statement has no port expression", expr.NAT)
		}
		port = portMinExpr.Any
	}

	if expr.RegProtoMax != 0 && expr.RegProtoMax != expr.RegProtoMin {
		portMaxExpr, ok := expr.reg.GetExpr(expr.RegProtoMax)
		if !ok || portMaxExpr.Any == nil {
			return nil, errors.Errorf("%T statement has no port expression", expr.NAT)
		}
		if port == nil {
			port = portMaxExpr.Any
		} else {
			port = map[string]interface{}{
				"range": [2]any{port, portMaxExpr.Any},
			}
		}
	}

	nat := map[string]interface{}{
		NATType(expr.Type).String(): struct {
			Family string `json:"family,omitempty"`
			Addr   any    `json:"addr,omitempty"`
			Port   any    `json:"port,omitempty"`
			Flags  any    `json:"flags,omitempty"`
		}{
			Family: family,
			Addr:   addr,
			Port:   port,
			Flags:  flag,
		},
	}

	return json.Marshal(nat)
}
