package encoders

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/wildberries-tech/pkt-tracer/internal/nftables/cache"

	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

type (
	CtKey    nfte.CtKey
	CtDir    uint32
	CtStatus uint32
	CtState  uint32
	CtEvents uint32
)

const (
	CtStateBitINVALID     CtState = CtState(nfte.CtStateBitINVALID)
	CtStateBitESTABLISHED CtState = CtState(nfte.CtStateBitESTABLISHED)
	CtStateBitRELATED     CtState = CtState(nfte.CtStateBitRELATED)
	CtStateBitNEW         CtState = CtState(nfte.CtStateBitNEW)
	CtStateBitUNTRACKED   CtState = CtState(nfte.CtStateBitUNTRACKED)
)

func (c CtKey) String() string {
	switch nfte.CtKey(c) {
	case nfte.CtKeySTATE:
		return "state"
	case nfte.CtKeyDIRECTION:
		return "direction"
	case nfte.CtKeySTATUS:
		return "status"
	case nfte.CtKeyMARK:
		return "mark" //nolint:goconst
	case nfte.CtKeySECMARK:
		return "secmark" //nolint:goconst
	case nfte.CtKeyEXPIRATION:
		return "expiration"
	case nfte.CtKeyHELPER:
		return "helper"
	case nfte.CtKeyL3PROTOCOL:
		return "l3proto"
	case nfte.CtKeySRC:
		return "saddr"
	case nfte.CtKeyDST:
		return "daddr"
	case nfte.CtKeyPROTOCOL:
		return "protocol"
	case nfte.CtKeyPROTOSRC:
		return "proto-src"
	case nfte.CtKeyPROTODST:
		return "proto-dst"
	case nfte.CtKeyLABELS:
		return "label"
	case nfte.CtKeyPKTS:
		return "packets"
	case nfte.CtKeyBYTES:
		return "bytes"
	case nfte.CtKeyAVGPKT:
		return "avgpkt"
	case nfte.CtKeyZONE:
		return "zone"
	case nfte.CtKeyEVENTMASK:
		return "event"
	}
	return "unknown"
}

func (c CtState) String() string {
	var st []string

	if c&CtStateBitINVALID != 0 {
		st = append(st, "invalid")
	}
	if c&CtStateBitESTABLISHED != 0 {
		st = append(st, "established")
	}
	if c&CtStateBitRELATED != 0 {
		st = append(st, "related")
	}
	if c&CtStateBitNEW != 0 {
		st = append(st, "new")
	}
	if c&CtStateBitUNTRACKED != 0 {
		st = append(st, "untracked")
	}

	return strings.Join(st, ",")
}

// CT DIR TYPE
const (
	IP_CT_DIR_ORIGINAL CtDir = iota
	IP_CT_DIR_REPLY
)

func (c CtDir) String() string {
	switch c {
	case IP_CT_DIR_ORIGINAL:
		return "original"
	case IP_CT_DIR_REPLY:
		return "reply"
	}
	return "unknown"
}

// CT STATUS
const (
	IPS_EXPECTED CtStatus = 1 << iota
	IPS_SEEN_REPLY
	IPS_ASSURED
	IPS_CONFIRMED
	IPS_SRC_NAT
	IPS_DST_NAT
	IPS_DYING CtStatus = 512
)

func (c CtStatus) String() string {
	var st []string
	if c&IPS_EXPECTED != 0 {
		st = append(st, "expected")
	}
	if c&IPS_SEEN_REPLY != 0 {
		st = append(st, "seen-reply")
	}
	if c&IPS_ASSURED != 0 {
		st = append(st, "assured")
	}
	if c&IPS_CONFIRMED != 0 {
		st = append(st, "confirmed")
	}
	if c&IPS_SRC_NAT != 0 {
		st = append(st, "snat")
	}
	if c&IPS_DST_NAT != 0 {
		st = append(st, "dnat")
	}
	if c&IPS_DYING != 0 {
		st = append(st, "dying")
	}

	return strings.Join(st, ",")
}

// CT EVENTS
const (
	IPCT_NEW CtEvents = iota
	IPCT_RELATED
	IPCT_DESTROY
	IPCT_REPLY
	IPCT_ASSURED
	IPCT_PROTOINFO
	IPCT_HELPER
	IPCT_MARK
	IPCT_SEQADJ
	IPCT_SECMARK
	IPCT_LABEL
)

func (c CtEvents) String() string {
	var events []string
	switch c {
	case c & (1 << IPCT_NEW):
		events = append(events, "new")
	case c & (1 << IPCT_RELATED):
		events = append(events, "related")
	case c & (1 << IPCT_DESTROY):
		events = append(events, "destroy")
	case c & (1 << IPCT_REPLY):
		events = append(events, "reply")
	case c & (1 << IPCT_ASSURED):
		events = append(events, "assured")
	case c & (1 << IPCT_PROTOINFO):
		events = append(events, "protoinfo")
	case c & (1 << IPCT_HELPER):
		events = append(events, "helper")
	case c & (1 << IPCT_MARK):
		events = append(events, "mark")
	case c & (1 << IPCT_SEQADJ):
		events = append(events, "seqadj")
	case c & (1 << IPCT_SECMARK):
		events = append(events, "secmark")
	case c & (1 << IPCT_LABEL):
		events = append(events, "label")
	}
	return strings.Join(events, ",")
}

type ExprCt struct {
	*nfte.Ct
	reg Register
}

func newCtEncoder(expr *nfte.Ct, reg Register) *ExprCt {
	return &ExprCt{Ct: expr, reg: reg}
}

func (expr *ExprCt) String() (string, error) {
	ct := fmt.Sprintf("ct %s", CtKey(expr.Key))
	if !expr.SourceRegister {
		if expr.Register == 0 {
			return "", errors.Errorf("%T expression has invalid destination register %d", expr.Ct, expr.Register)
		}
		expr.reg.InsertExpr(expr.Register,
			cache.RegEntry{
				ExprStr: ct,
				Expr:    expr.Ct,
			})
		return "", nil
	}
	srcReg, ok := expr.reg.GetExpr(expr.Register)

	if !ok {
		return "", errors.Errorf("%T statement has no expression", expr.Ct)
	}

	exp := srcReg.ExprStr

	return fmt.Sprintf("%s set %s", ct, exp), nil
}

func (expr *ExprCt) MarshalJSON() ([]byte, error) {
	ct := map[string]interface{}{
		"ct": struct {
			Key string `json:"key"`
		}{
			Key: CtKey(expr.Key).String(),
		},
	}
	if !expr.SourceRegister {
		if expr.Register == 0 {
			return nil, errors.Errorf("%T expression has invalid destination register %d", expr.Ct, expr.Register)
		}
		expr.reg.InsertExpr(expr.Register, cache.RegEntry{Any: ct})
		return []byte("{}"), nil
	}

	srcReg, ok := expr.reg.GetExpr(expr.Register)

	if !ok || srcReg.Any == nil {
		return nil, errors.Errorf("%T statement has no expression", expr.Ct)
	}

	mangle := map[string]interface{}{
		"mangle": struct {
			Key any `json:"key"`
			Val any `json:"value"`
		}{
			Key: ct,
			Val: srcReg.Any,
		},
	}
	return json.Marshal(mangle)
}

var CtDesk = map[nfte.CtKey]func(b []byte) string{
	nfte.CtKeySTATE:      BytesToCtStateString,
	nfte.CtKeyDIRECTION:  BytesToCtDirString,
	nfte.CtKeySTATUS:     BytesToCtStatusString,
	nfte.CtKeyMARK:       LEBytesToIntString,
	nfte.CtKeySECMARK:    LEBytesToIntString,
	nfte.CtKeyEXPIRATION: BytesToTimeString,
	nfte.CtKeyHELPER:     BytesToString,
	nfte.CtKeyL3PROTOCOL: BytesToNfProtoString,
	nfte.CtKeySRC:        BytesToInvalidType,
	nfte.CtKeyDST:        BytesToInvalidType,
	nfte.CtKeyPROTOCOL:   BytesToProtoString,
	nfte.CtKeyPROTOSRC:   BytesToDecimalString,
	nfte.CtKeyPROTODST:   BytesToDecimalString,
	nfte.CtKeyLABELS:     BytesToDecimalString,
	nfte.CtKeyPKTS:       LEBytesToIntString,
	nfte.CtKeyBYTES:      LEBytesToIntString,
	nfte.CtKeyAVGPKT:     LEBytesToIntString,
	nfte.CtKeyZONE:       LEBytesToIntString,
	nfte.CtKeyEVENTMASK:  BytesToCtEventString,
}
