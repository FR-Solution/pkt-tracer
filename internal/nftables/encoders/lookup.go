package encoders

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/wildberries-tech/pkt-tracer/internal/nftables/cache"

	"github.com/google/nftables"
	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type ExprLookup struct {
	*nfte.Lookup
	table *nftables.Table
	reg   Register
	set   SetsHolderFace
}

func newLookupEncoder(expr *nfte.Lookup, table *nftables.Table, reg Register, set SetsHolderFace) *ExprLookup {
	return &ExprLookup{
		Lookup: expr,
		table:  table,
		reg:    reg,
		set:    set,
	}
}

func (expr *ExprLookup) String() (string, error) {
	containExpression := func(s string) bool {
		re := regexp.MustCompile(`[()&|^<>]`)
		return re.MatchString(s)
	}
	if expr.set == nil {
		return "", errors.Errorf("set must be implement for the '%T' expression", expr)
	}
	if expr.reg == nil {
		return "", errors.Errorf("register must be implement for the '%T' expression", expr)
	}
	sets, ok := expr.set.GetSet(cache.SetKey{
		TableName: expr.table.Name,
		SetName:   expr.SetName,
		SetId:     expr.SetID,
	})

	if !ok {
		conn, err := nftables.New()
		if err != nil {
			return "", err
		}
		defer func() { _ = conn.CloseLasting() }()
		set, err := conn.GetSetByName(expr.table, expr.SetName)
		if err != nil {
			return "", err
		}
		if set != nil {
			elems, err := conn.GetSetElements(set)
			if err != nil {
				return "", err
			}
			sets = &cache.SetEntry{
				Set:      *set,
				Elements: elems,
			}
			expr.set.InsertSet(cache.SetKey{
				TableName: expr.table.Name,
				SetName:   expr.SetName,
				SetId:     expr.SetID,
			},
				sets,
			)
		}
	}
	if sets == nil {
		return "", errors.Errorf(`unknown set '%s' in %T expression`, expr.SetName, expr.Lookup)
	}

	srcReg, ok := expr.reg.GetExpr(expr.SourceRegister)
	if !ok {
		return "", errors.Errorf("%T expression has no left hand side", expr.Lookup)
	}
	left := srcReg.ExprStr

	right := fmt.Sprintf(`@%s`, expr.SetName)
	sb := strings.Builder{}
	if sets.Anonymous {
		switch sets.KeyType {
		case nftables.TypeVerdict,
			nftables.TypeString,
			nftables.TypeIFName:
			sb.Reset()
			sb.WriteByte('{')
			for i := range sets.Elements {
				sb.WriteString(RawBytes(sets.Elements[i].Key).String())
				if i < len(sets.Elements)-1 {
					sb.WriteByte(',')
				}
			}
			sb.WriteByte('}')
			right = sb.String()
			sb.Reset()
		case nftables.TypeIPAddr,
			nftables.TypeIP6Addr:
			sb.Reset()
			sb.WriteByte('{')
			for i := range sets.Elements {
				sb.WriteString(RawBytes(sets.Elements[i].Key).Ip().String())
				if i < len(sets.Elements)-1 {
					sb.WriteByte(',')
				}
			}
			sb.WriteByte('}')
			right = sb.String()
			sb.Reset()
		case nftables.TypeBitmask,
			nftables.TypeLLAddr,
			nftables.TypeEtherAddr,
			nftables.TypeTCPFlag,
			nftables.TypeMark,
			nftables.TypeUID,
			nftables.TypeGID:
			sb.Reset()
			sb.WriteByte('{')
			for i := range sets.Elements {
				sb.WriteString(RawBytes(sets.Elements[i].Key).Text(baseHex))
				if i < len(sets.Elements)-1 {
					sb.WriteByte(',')
				}
			}
			sb.WriteByte('}')
			right = sb.String()
			sb.Reset()
		default:
			sb.Reset()
			sb.WriteByte('{')
			for i := range sets.Elements {
				sb.WriteString(RawBytes(sets.Elements[i].Key).Text(baseDec))
				if i < len(sets.Elements)-1 {
					sb.WriteByte(',')
				}
			}
			sb.WriteByte('}')
			right = sb.String()
			sb.Reset()
		}
	}

	if expr.IsDestRegSet {
		sb.Reset()
		sb.WriteString(left)

		if expr.DestRegister != unix.NFT_REG_VERDICT {
			sb.WriteString(" map ")
		} else {
			sb.WriteString(" vmap ")
		}
		sb.WriteString(right)
		if expr.DestRegister != unix.NFT_REG_VERDICT {
			expr.reg.InsertExpr(expr.DestRegister, cache.RegEntry{ExprStr: sb.String()})
			return "", nil
		}
		return sb.String(), nil
	}

	if containExpression(left) {
		op := CmpOp(nfte.CmpOpEq)
		if expr.Invert {
			op = CmpOp(nfte.CmpOpNeq)
		}
		left = fmt.Sprintf("(%s) %s", left, op)
	}

	return fmt.Sprintf("%s %s", left, right), nil
}

func (expr *ExprLookup) MarshalJSON() ([]byte, error) {
	srcReg, ok := expr.reg.GetExpr(expr.SourceRegister)
	if !ok {
		return nil, errors.Errorf("%T expression has no left hand side", expr.Lookup)
	}
	setName := fmt.Sprintf(`@%s`, expr.SetName)
	if expr.IsDestRegSet {
		mapExp := struct {
			Key  any    `json:"key"`
			Data string `json:"data"`
		}{
			Key:  srcReg.Any,
			Data: setName,
		}

		if expr.DestRegister != unix.NFT_REG_VERDICT {
			m := map[string]interface{}{
				"map": mapExp,
			}
			expr.reg.InsertExpr(expr.DestRegister, cache.RegEntry{Any: m})
			return []byte("{}"), nil
		}
		m := map[string]interface{}{
			"vmap": mapExp,
		}
		return EncodeJSON(m, false)
	}
	op := nfte.CmpOpEq
	if expr.Invert {
		op = nfte.CmpOpNeq
	}
	match := map[string]interface{}{
		"match": struct {
			Op    string `json:"op"`
			Left  any    `json:"left"`
			Right any    `json:"right"`
		}{
			Op:    CmpOp(op).String(),
			Left:  srcReg.Any,
			Right: setName,
		},
	}
	return EncodeJSON(match, false)
}
