package encoders

import (
	"fmt"

	nfte "github.com/google/nftables/expr"
)

type ExprTarget struct {
	*nfte.Target
}

func newTargetEncoder(expr *nfte.Target) *ExprTarget {
	return &ExprTarget{Target: expr}
}

func (expr *ExprTarget) String() (string, error) {
	return fmt.Sprintf(`xt target %q`, expr.Name), nil
}

func (expr *ExprTarget) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`{"xt":{"type":"target","name":%q}}`, expr.Name)), nil
}
