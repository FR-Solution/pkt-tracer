package encoders

import (
	"encoding/json"
	"fmt"

	"github.com/wildberries-tech/pkt-tracer/internal/nftables/cache"

	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

type MetaKey nfte.MetaKey

func (m MetaKey) String() string {
	switch nfte.MetaKey(m) {
	case nfte.MetaKeyLEN:
		return "length"
	case nfte.MetaKeyPROTOCOL:
		return "protocol"
	case nfte.MetaKeyPRIORITY:
		return "priority"
	case nfte.MetaKeyMARK:
		return "mark"
	case nfte.MetaKeyIIF:
		return "iif"
	case nfte.MetaKeyOIF:
		return "oif"
	case nfte.MetaKeyIIFNAME:
		return "iifname"
	case nfte.MetaKeyOIFNAME:
		return "oifname"
	case nfte.MetaKeyIIFTYPE:
		return "iiftype"
	case nfte.MetaKeyOIFTYPE:
		return "oiftype"
	case nfte.MetaKeySKUID:
		return "skuid"
	case nfte.MetaKeySKGID:
		return "skgid"
	case nfte.MetaKeyNFTRACE:
		return "nftrace"
	case nfte.MetaKeyRTCLASSID:
		return "rtclassid"
	case nfte.MetaKeySECMARK:
		return "secmark"
	case nfte.MetaKeyNFPROTO:
		return "nfproto"
	case nfte.MetaKeyL4PROTO:
		return "l4proto"
	case nfte.MetaKeyBRIIIFNAME:
		return "ibrname"
	case nfte.MetaKeyBRIOIFNAME:
		return "obrname"
	case nfte.MetaKeyPKTTYPE:
		return "pkttype"
	case nfte.MetaKeyCPU:
		return "cpu"
	case nfte.MetaKeyIIFGROUP:
		return "iifgroup"
	case nfte.MetaKeyOIFGROUP:
		return "oifgroup"
	case nfte.MetaKeyCGROUP:
		return "cgroup"
	case nfte.MetaKeyPRANDOM:
		return "random"
	}
	return "unknown"
}

func (m MetaKey) IsUnqualified() bool {
	switch nfte.MetaKey(m) {
	case nfte.MetaKeyIIF,
		nfte.MetaKeyOIF,
		nfte.MetaKeyIIFNAME,
		nfte.MetaKeyOIFNAME,
		nfte.MetaKeyIIFGROUP,
		nfte.MetaKeyOIFGROUP:
		return true
	default:
		return false
	}
}

type ExprMeta struct {
	*nfte.Meta
	reg Register
}

func (m ExprMeta) metaDataToString(data []byte) string {
	switch m.Key {
	case nfte.MetaKeyIIFNAME,
		nfte.MetaKeyOIFNAME,
		nfte.MetaKeyBRIIIFNAME,
		nfte.MetaKeyBRIOIFNAME:
		return RawBytes(data).String()
	case nfte.MetaKeyPROTOCOL, nfte.MetaKeyNFPROTO, nfte.MetaKeyL4PROTO:
		proto := ProtoType(int(RawBytes(data).Uint64())).String() //nolint:gosec

		return proto
	default:
		return RawBytes(data).Text(baseDec)
	}
}

func newMetaEncoder(expr *nfte.Meta, reg Register) *ExprMeta {
	return &ExprMeta{Meta: expr, reg: reg}
}

func (expr *ExprMeta) String() (string, error) {
	metaKey := MetaKey(expr.Key)
	metaExpr := metaKey.String()
	if !metaKey.IsUnqualified() {
		metaExpr = fmt.Sprintf("meta %s", metaKey)
	}
	if !expr.SourceRegister {
		if expr.Register == 0 {
			return "", errors.Errorf("%T expression has invalid destination register %d", expr.Meta, expr.Register)
		}

		expr.reg.InsertExpr(expr.Register,
			cache.RegEntry{
				ExprStr: metaExpr,
				Expr:    expr.Meta,
				Any:     expr,
			})
		return "", nil
	}
	srcReg, ok := expr.reg.GetExpr(expr.Register)
	if !ok {
		return "", errors.Errorf("%T statement has no expression", expr.Meta)
	}
	exp := srcReg.ExprStr

	switch t := srcReg.Expr.(type) {
	case *nfte.Immediate:
		exp = expr.metaDataToString(t.Data)
	}

	metaExpr = fmt.Sprintf("%s set %s", metaKey, exp)
	if !metaKey.IsUnqualified() {
		metaExpr = fmt.Sprintf("meta %s set %s", metaKey, exp)
	}

	return metaExpr, nil
}

func (expr *ExprMeta) MarshalJSON() ([]byte, error) {
	meta := map[string]interface{}{
		"meta": struct {
			Key string `json:"key"`
		}{
			Key: MetaKey(expr.Key).String(),
		},
	}
	if !expr.SourceRegister {
		if expr.Register == 0 {
			return nil, errors.Errorf("%T expression has invalid destination register %d", expr.Meta, expr.Register)
		}
		expr.reg.InsertExpr(expr.Register,
			cache.RegEntry{
				Any:  meta,
				Expr: expr.Meta,
			})
		return []byte("{}"), nil
	}

	srcReg, ok := expr.reg.GetExpr(expr.Register)
	if !ok {
		return nil, errors.Errorf("%T statement has no expression", expr.Meta)
	}

	mangle := map[string]interface{}{
		"mangle": struct {
			Key any `json:"key"`
			Val any `json:"value"`
		}{
			Key: meta,
			Val: srcReg.Any,
		},
	}

	return json.Marshal(mangle)
}
