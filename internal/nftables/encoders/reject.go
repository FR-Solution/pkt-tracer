package encoders

import (
	"encoding/json"
	"fmt"
	"strings"

	nfte "github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type ExprReject struct {
	*nfte.Reject
}

func newRejectEncoder(expr *nfte.Reject) *ExprReject {
	return &ExprReject{Reject: expr}
}

func (e *ExprReject) TypeStr() string {
	switch e.Type {
	case unix.NFT_REJECT_TCP_RST:
		return "tcp reset"
	case unix.NFT_REJECT_ICMPX_UNREACH:
		if e.Code == unix.NFT_REJECT_ICMPX_PORT_UNREACH {
			break
		}
		return "icmpx"
	case unix.NFT_REJECT_ICMP_UNREACH:
		switch e.Code {
		case unix.NFPROTO_IPV4:
			return "icmp"
		case unix.NFPROTO_IPV6:
			return "icmpv6"
		}
	}
	return ""
}

func (expr *ExprReject) String() (string, error) {
	sb := strings.Builder{}
	sb.WriteString("reject")
	t := expr.TypeStr()
	if t != "" {
		sb.WriteString(fmt.Sprintf(" with %s %d", t, expr.Code))
	}

	return sb.String(), nil
}

func (expr *ExprReject) MarshalJSON() ([]byte, error) {
	if expr.TypeStr() == "" && expr.Code == 0 {
		return []byte(`{"reject":null}`), nil
	}
	reject := map[string]interface{}{
		"reject": struct {
			Type string `json:"type,omitempty"`
			Code uint8  `json:"expr,omitempty"`
		}{
			Type: expr.TypeStr(),
			Code: expr.Code,
		},
	}

	return json.Marshal(reject)
}
