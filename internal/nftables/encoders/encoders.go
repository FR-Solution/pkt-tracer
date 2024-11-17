package encoders

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/wildberries-tech/pkt-tracer/internal/nftables/cache"

	"github.com/google/nftables"
	nfte "github.com/google/nftables/expr"
)

type Encoder interface {
	MarshalJSON() ([]byte, error)
	String() (string, error)
}

type (
	ruleExprs struct {
		exprs []nfte.Any
		table *nftables.Table
		reg   Register
	}
	ruleExpr struct {
		expr    nfte.Any
		table   *nftables.Table
		reg     Register
		hdrDesc *ProtoDescPtr
	}

	RuleEncode nftables.Rule
)

func newRuleExprs(exprs []nfte.Any, table *nftables.Table, reg Register) *ruleExprs {
	return &ruleExprs{
		exprs: exprs,
		table: table,
		reg:   reg,
	}
}

func newRuleExpr(expr nfte.Any, table *nftables.Table, reg Register, hdrDesc *ProtoDescPtr) *ruleExpr {
	return &ruleExpr{
		expr:    expr,
		table:   table,
		reg:     reg,
		hdrDesc: hdrDesc,
	}
}

// MarshalJSON json Marshaler
func (e *ruleExpr) MarshalJSON() ([]byte, error) {
	return json.Marshal(newExprEncoder(e))
}

//nolint:gocyclo
func newExprEncoder(e *ruleExpr) Encoder {
	var v Encoder
	switch t := e.expr.(type) {
	case *nfte.Bitwise:
		v = newBitwiseEncoder(t, e.reg, e.hdrDesc)
	case *nfte.Byteorder:
		v = newByteorderEncoder(t, e.reg)
	case *nfte.Connlimit:
		v = newConnlimitEncoder(t)
	case *nfte.Counter:
		v = newCounterEncoder(t)
	case *nfte.Ct:
		v = newCtEncoder(t, e.reg)
	case *nfte.Dup:
		v = newDupEncoder(t, e.reg)
	case *nfte.Dynset:
		v = newDynsetEncoder(t, e.reg)
	case *nfte.Meta:
		v = newMetaEncoder(t, e.reg)
	case *nfte.Cmp:
		v = newCmpEncoder(t, e.reg, e.hdrDesc)
	case *nfte.Masq:
		v = newMasqEncoder(t, e.reg)
	case *nfte.Exthdr:
		v = newExthdrEncoder(t, e.reg)
	case *nfte.Fib:
		v = newFibEncoder(t, e.reg)
	case *nfte.FlowOffload:
		v = newFlowOffloadEncoder(t)
	case *nfte.Hash:
		v = newHashEncoder(t, e.reg)
	case *nfte.Immediate:
		v = newImmediateEncoder(t, e.reg)
	case *nfte.Limit:
		v = newLimitEncoder(t)
	case *nfte.Log:
		v = newLogEncoder(t)
	case *nfte.Lookup:
		v = newLookupEncoder(t, e.table, e.reg, &cache.SetsHolder)
	case *nfte.Match:
		v = newMatchEncoder(t)
	case *nfte.NAT:
		v = newNATEncoder(t, e.reg)
	case *nfte.Notrack:
		v = newNotrackEncoder(t)
	case *nfte.Numgen:
		v = newNumgenEncoder(t, e.reg)
	case *nfte.Objref:
		v = newObjrefEncoder(t)
	case *nfte.Payload:
		v = newPayloadEncoder(t, e.reg, e.hdrDesc)
	case *nfte.Queue:
		v = newQueueEncoder(t)
	case *nfte.Quota:
		v = newQuotaEncoder(t)
	case *nfte.Range:
		v = newRangeEncoder(t, e.reg)
	case *nfte.Redir:
		v = newRedirEncoder(t, e.reg)
	case *nfte.Reject:
		v = newRejectEncoder(t)
	case *nfte.Rt:
		v = newRtEncoder(t, e.reg)
	case *nfte.Socket:
		v = newSocketEncoder(t, e.reg)
	case *nfte.Target:
		v = newTargetEncoder(t)
	case *nfte.TProxy:
		v = newTProxyEncoder(t, e.reg)
	case *nfte.Verdict:
		v = newVerdictEncoder(t)
	}
	return v
}

// MarshalJSON json Marshaler
func (e *ruleExprs) MarshalJSON() ([]byte, error) {
	return e.encoderWithEscape(false)
}

func (e *ruleExprs) encoderWithEscape(escape bool) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	var hdrDesc ProtoDescPtr
	if e.exprs == nil {
		_, _ = buf.WriteString("null")
	} else {
		_ = buf.WriteByte('[')
		for i := range e.exprs {
			b, err := EncodeJSON(newRuleExpr(e.exprs[i], e.table, e.reg, &hdrDesc), escape)
			if err != nil {
				return nil, err
			}
			if string(b) == "{}" {
				continue
			}
			buf.Write(b)
			if i < len(e.exprs)-1 {
				_ = buf.WriteByte(',')
			}
		}
		_ = buf.WriteByte(']')
	}
	return buf.Bytes(), nil
}

// EncodeJSON - json encoder with escape parameter
func EncodeJSON(v any, escape bool) ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(escape)
	switch t := v.(type) {
	case nftables.Rule:
		v = newRuleExprs(t.Exprs, t.Table, cache.NewRegisters())
	case *nftables.Rule:
		v = newRuleExprs(t.Exprs, t.Table, cache.NewRegisters())
	case RuleEncode:
		v = newRuleExprs(t.Exprs, t.Table, cache.NewRegisters())
	case *RuleEncode:
		v = newRuleExprs(t.Exprs, t.Table, cache.NewRegisters())
	case ruleExpr:
		v = newExprEncoder(&t)
	case *ruleExpr:
		v = newExprEncoder(t)
	}
	err := enc.Encode(v)
	return bytes.TrimRight(buf.Bytes(), "\n"), err
}

func (r RuleEncode) String() (string, error) {
	sb := strings.Builder{}
	expr, err := newRuleExprs(r.Exprs, r.Table, cache.NewRegisters()).String()
	if err != nil {
		return "", err
	}
	if expr != "" {
		sb.WriteString(fmt.Sprintf("%s #handle %d", expr, r.Handle))
	}
	return sb.String(), nil
}

func (e *ruleExprs) String() (string, error) {
	var hdrDesc ProtoDescPtr
	sb := strings.Builder{}
	for i := range e.exprs {
		str, err := newRuleExpr(e.exprs[i], e.table, e.reg, &hdrDesc).String()
		if err != nil {
			return "", err
		}
		n, _ := sb.WriteString(str)
		if i < len(e.exprs)-1 && n > 0 {
			_ = sb.WriteByte(' ')
		}
	}
	return sb.String(), nil
}

func (e *ruleExpr) String() (string, error) {
	sb := strings.Builder{}
	v := newExprEncoder(e)
	if v != nil {
		str, err := v.String()
		if err != nil {
			return "", err
		}
		_, _ = sb.WriteString(str)
	}
	return sb.String(), nil
}
