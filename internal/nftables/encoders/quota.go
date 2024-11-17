package encoders

import (
	"encoding/json"
	"fmt"

	nfte "github.com/google/nftables/expr"
)

type ExprQuota struct {
	*nfte.Quota
}

func newQuotaEncoder(expr *nfte.Quota) *ExprQuota {
	return &ExprQuota{Quota: expr}
}

func (q *ExprQuota) Rate() (val uint64, unit string) {
	return getRate(q.Bytes)
}

func (expr *ExprQuota) String() (string, error) {
	val, u := expr.Rate()
	return fmt.Sprintf("quota %s%d %s", map[bool]string{true: "over ", false: ""}[expr.Over],
		val, u), nil
}

func (expr *ExprQuota) MarshalJSON() ([]byte, error) {
	val, u := expr.Rate()
	quota := map[string]interface{}{
		"quota": struct {
			Val  uint64 `json:"val"`
			Unit string `json:"val_unit"`
		}{
			Val:  val,
			Unit: u,
		},
	}

	return json.Marshal(quota)
}
