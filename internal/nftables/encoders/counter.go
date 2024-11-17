package encoders

import (
	"fmt"

	nfte "github.com/google/nftables/expr"
)

type ExprCounter struct {
	*nfte.Counter
}

func newCounterEncoder(expr *nfte.Counter) *ExprCounter {
	return &ExprCounter{expr}
}

func (expr *ExprCounter) String() (string, error) {
	return "counter packets 0 bytes 0", nil
}

func (expr *ExprCounter) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`{"counter":{"bytes":%d,"packets":%d}}`, expr.Bytes, expr.Packets)), nil
}
