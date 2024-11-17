package encoders

import (
	"fmt"

	nfte "github.com/google/nftables/expr"
)

type ExprMatch struct {
	*nfte.Match
}

func newMatchEncoder(expr *nfte.Match) *ExprMatch {
	return &ExprMatch{Match: expr}
}

func (expr *ExprMatch) String() (string, error) {
	return fmt.Sprintf(`xt match %q`, expr.Name), nil
}

func (expr *ExprMatch) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`{"xt":{"type":"match","name":%q}}`, expr.Name)), nil
}
