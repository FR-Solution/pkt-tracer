package encoders

import (
	nfte "github.com/google/nftables/expr"
)

type ExprNotrack struct {
	*nfte.Notrack
}

func newNotrackEncoder(expr *nfte.Notrack) *ExprNotrack {
	return &ExprNotrack{Notrack: expr}
}

func (expr *ExprNotrack) String() (string, error) {
	return "notrack", nil
}

func (expr *ExprNotrack) MarshalJSON() ([]byte, error) {
	return []byte(`{"notrack":null}`), nil
}
