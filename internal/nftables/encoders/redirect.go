package encoders

import (
	"encoding/json"

	nfte "github.com/google/nftables/expr"
)

type ExprRedir struct {
	*nfte.Redir
	reg Register
}

func newRedirEncoder(expr *nfte.Redir, reg Register) *ExprRedir {
	return &ExprRedir{Redir: expr, reg: reg}
}

func (expr *ExprRedir) String() (string, error) {
	nat := newNATEncoder(
		&nfte.NAT{
			Type:        NATTypeRedir,
			Persistent:  (expr.Flags & nfte.NF_NAT_RANGE_PERSISTENT) != 0,
			Random:      (expr.Flags & nfte.NF_NAT_RANGE_PROTO_RANDOM) != 0,
			FullyRandom: (expr.Flags & nfte.NF_NAT_RANGE_PROTO_RANDOM_FULLY) != 0,
			RegProtoMin: expr.RegisterProtoMin,
			RegProtoMax: expr.RegisterProtoMax,
		}, expr.reg,
	)

	return nat.String()
}

func (expr *ExprRedir) MarshalJSON() ([]byte, error) {
	nat := &nfte.NAT{
		Type:        NATTypeRedir,
		Persistent:  (expr.Flags & nfte.NF_NAT_RANGE_PERSISTENT) != 0,
		Random:      (expr.Flags & nfte.NF_NAT_RANGE_PROTO_RANDOM) != 0,
		FullyRandom: (expr.Flags & nfte.NF_NAT_RANGE_PROTO_RANDOM_FULLY) != 0,
		RegProtoMin: expr.RegisterProtoMin,
		RegProtoMax: expr.RegisterProtoMax,
	}
	return json.Marshal(&ExprNAT{NAT: nat, reg: expr.reg})
}
