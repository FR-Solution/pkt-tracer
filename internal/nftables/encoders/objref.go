package encoders

import (
	"fmt"
	"strings"

	nfte "github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type ObjType int

const (
	ObjCounter   ObjType = unix.NFT_OBJECT_COUNTER
	ObjQuota     ObjType = unix.NFT_OBJECT_QUOTA
	ObjCtHelper  ObjType = unix.NFT_OBJECT_CT_HELPER
	ObjLimit     ObjType = unix.NFT_OBJECT_LIMIT
	ObjCtTimeout ObjType = unix.NFT_OBJECT_CT_TIMEOUT
	ObjSecMark   ObjType = unix.NFT_OBJECT_SECMARK
	ObjSynProxy  ObjType = unix.NFT_OBJECT_SYNPROXY
	ObjCtExpect  ObjType = unix.NFT_OBJECT_CT_EXPECT
)

func (o ObjType) String() string {
	switch o {
	case ObjCounter:
		return "counter"
	case ObjQuota:
		return "quota"
	case ObjCtHelper:
		return "ct helper"
	case ObjLimit:
		return "limit"
	case ObjCtTimeout:
		return "ct timeout"
	case ObjSecMark:
		return "secmark"
	case ObjSynProxy:
		return "synproxy"
	case ObjCtExpect:
		return "ct expectation"
	}
	return "unknown"
}

type ExprObjref struct {
	*nfte.Objref
}

func newObjrefEncoder(expr *nfte.Objref) *ExprObjref {
	return &ExprObjref{Objref: expr}
}

func (expr *ExprObjref) String() (string, error) {
	sb := strings.Builder{}
	objType := ObjType(expr.Type)
	switch objType {
	case ObjCtHelper:
		sb.WriteString("ct helper set ")
	case ObjCtTimeout:
		sb.WriteString("ct timeout set ")
	case ObjCtExpect:
		sb.WriteString("ct expectation set ")
	case ObjSecMark:
		sb.WriteString("meta secmark set ")
	default:
		sb.WriteString(fmt.Sprintf("%s name ", objType))
	}
	sb.WriteString(expr.Name)
	return sb.String(), nil
}

func (expr *ExprObjref) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`{%q:%q}`, expr.Type, expr.Name)), nil
}
