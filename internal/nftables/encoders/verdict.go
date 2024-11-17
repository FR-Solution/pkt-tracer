package encoders

import (
	"fmt"

	nfte "github.com/google/nftables/expr"
)

type VerdictKind nfte.VerdictKind

var verdictMap = map[nfte.VerdictKind]string{
	nfte.VerdictReturn:   "return",
	nfte.VerdictGoto:     "goto",
	nfte.VerdictJump:     "jump",
	nfte.VerdictBreak:    "break",
	nfte.VerdictContinue: "continue",
	nfte.VerdictDrop:     "drop",
	nfte.VerdictAccept:   "accept",
	nfte.VerdictStolen:   "storlen",
	nfte.VerdictQueue:    "queue",
	nfte.VerdictRepeat:   "repeat",
	nfte.VerdictStop:     "stop",
}

func (v VerdictKind) String() (verdict string) {
	verdict, ok := verdictMap[nfte.VerdictKind(v)]
	if !ok {
		verdict = "unknown"
	}
	return verdict
}

type ExprVerdict struct {
	*nfte.Verdict
}

func newVerdictEncoder(expr *nfte.Verdict) *ExprVerdict {
	return &ExprVerdict{Verdict: expr}
}

func (expr *ExprVerdict) String() (string, error) {
	if expr.Chain == "" {
		return VerdictKind(expr.Kind).String(), nil
	}
	return fmt.Sprintf("%s %s", VerdictKind(expr.Kind).String(), expr.Chain), nil
}

func (expr *ExprVerdict) MarshalJSON() ([]byte, error) {
	if expr.Chain == "" {
		return []byte(fmt.Sprintf(`{%q:null}`, VerdictKind(expr.Kind).String())), nil
	}
	return []byte(fmt.Sprintf(`{%q:{"target":%q}}`, VerdictKind(expr.Kind).String(), expr.Chain)), nil
}
