package encoders

import (
	"fmt"

	nfte "github.com/google/nftables/expr"
)

type ExprFlowOffload struct {
	*nfte.FlowOffload
}

func newFlowOffloadEncoder(expr *nfte.FlowOffload) *ExprFlowOffload {
	return &ExprFlowOffload{FlowOffload: expr}
}

func (expr *ExprFlowOffload) String() (string, error) {
	return fmt.Sprintf("flow add @%s", expr.Name), nil
}

func (expr *ExprFlowOffload) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`{"flow":{"op":"add","flowtable":%q}}`, expr.Name)), nil
}
