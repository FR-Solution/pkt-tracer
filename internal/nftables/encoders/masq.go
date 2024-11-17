package encoders

import (
	"encoding/json"

	nfte "github.com/google/nftables/expr"
)

type ExprMasq struct {
	*nfte.Masq
	reg Register
}

func newMasqEncoder(expr *nfte.Masq, reg Register) *ExprMasq {
	return &ExprMasq{Masq: expr, reg: reg}
}

func (expr *ExprMasq) String() (string, error) {
	masq := newNATEncoder(
		&nfte.NAT{
			Type:        NATTypeMASQ,
			Persistent:  expr.Persistent,
			Random:      expr.Random,
			FullyRandom: expr.FullyRandom,
			RegProtoMin: expr.RegProtoMin,
			RegProtoMax: expr.RegProtoMax,
		},
		expr.reg,
	)
	return masq.String()
}

func (expr *ExprMasq) MarshalJSON() ([]byte, error) {
	masq := &nfte.NAT{
		Type:        NATTypeMASQ,
		Persistent:  expr.Persistent,
		Random:      expr.Random,
		FullyRandom: expr.FullyRandom,
		RegProtoMin: expr.RegProtoMin,
		RegProtoMax: expr.RegProtoMax,
	}
	return json.Marshal(&ExprNAT{NAT: masq, reg: expr.reg})
}
