package encoders

import (
	"encoding/json"
	"fmt"

	nfte "github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type ExprConnlimit struct {
	*nfte.Connlimit
}

func newConnlimitEncoder(expr *nfte.Connlimit) *ExprConnlimit {
	return &ExprConnlimit{expr}
}

func (expr *ExprConnlimit) String() (string, error) {
	return fmt.Sprintf("ct count %s%d",
		map[bool]string{true: "over ", false: ""}[expr.Flags != 0], expr.Count), nil
}

func (expr *ExprConnlimit) MarshalJSON() ([]byte, error) {
	cl := map[string]interface{}{
		"ct count": struct {
			Val uint32 `json:"val"`
			Inv bool   `json:"inv,omitempty"`
		}{
			Val: expr.Count,
			Inv: expr.Flags&unix.NFT_LIMIT_F_INV != 0,
		},
	}
	return json.Marshal(cl)
}
