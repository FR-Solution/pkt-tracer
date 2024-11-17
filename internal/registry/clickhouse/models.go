package clickhouse

import (
	"fmt"
	"reflect"
	"time"
	"unsafe"

	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"
	"github.com/wildberries-tech/pkt-tracer/internal/registry/scopes"
	"github.com/wildberries-tech/pkt-tracer/pkg/meta"

	"github.com/H-BF/corlib/pkg/filter"
	sq "github.com/Masterminds/squirrel"
)

type (
	// TraceDB - put trace into DB
	TraceDB struct {
		// trace id
		TrId uint32 `ch:"trace_id"`
		// nftables table name
		Table string `ch:"table"`
		// nftables chain name
		Chain string `ch:"chain"`
		// nftables jump to a target name
		JumpTarget string `ch:"jump_target"`
		// nftables rule number
		RuleHandle uint64 `ch:"handle"`
		// protocols family
		Family string `ch:"family"`
		// input network interface
		Iifname string `ch:"ifin"`
		// output network interface
		Oifname string `ch:"ifout"`
		// source mac address
		SMacAddr string `ch:"mac_s"`
		// destination mac address
		DMacAddr string `ch:"mac_d"`
		// source ip address
		SAddr string `ch:"ip_s"`
		// destination ip address
		DAddr string `ch:"ip_d"`
		// source port
		SPort uint32 `ch:"sport"`
		// destination port
		DPort uint32 `ch:"dport"`
		// name of the security group for src ip
		SSgName string `ch:"sgname_s"`
		// name of the security group for dst ip
		DSgName string `ch:"sgname_d"`
		// name of the network for src ip
		SSgNet string `ch:"sgnet_s"`
		// name of the network for dst ip
		DSgNet string `ch:"sgnet_d"`
		// length packet
		Length uint32 `ch:"len"`
		// ip protocol (tcp/udp/icmp/...)
		IpProto string `ch:"ip_proto"`
		// verdict for the rule
		Verdict string `ch:"verdict"`
		// rule expression
		Rule string `ch:"rule"`
		// agent identifier
		UserAgent string `ch:"agent_id"`
		// time stamps
		Timestamp time.Time `ch:"timestamp"`
	}

	// FetchTraceDB - fetch trace from DB
	FetchTraceDB struct {
		// trace id
		TrId uint32 `ch:"trace_id"`
		// table id
		TableId uint64 `ch:"table_id"`
		// nftables table name
		Table string `ch:"table_name"`
		// nftables chain name
		Chain string `ch:"chain_name"`
		// nftables jump to a target name
		JumpTarget string `ch:"jump_target"`
		// nftables rule number
		RuleHandle uint64 `ch:"handle"`
		// rule expression
		Rule string `ch:"rule"`
		// verdict for the rule
		Verdict string `ch:"verdict"`
		// input network interface
		Iifname string `ch:"ifin"`
		// output network interface
		Oifname string `ch:"ifout"`
		// protocols family
		Family string `ch:"family"`
		// ip protocol (tcp/udp/icmp/...)
		IpProto string `ch:"ip_proto"`
		// length packet
		Length uint32 `ch:"len"`
		// source mac address
		SMacAddr string `ch:"mac_s"`
		// destination mac address
		DMacAddr string `ch:"mac_d"`
		// source ip address
		SAddr string `ch:"ip_s"`
		// destination ip address
		DAddr string `ch:"ip_d"`
		// source port
		SPort uint32 `ch:"sport"`
		// destination port
		DPort uint32 `ch:"dport"`
		// name of the security group for src ip
		SSgName string `ch:"sgname_s"`
		// name of the security group for dst ip
		DSgName string `ch:"sgname_d"`
		// name of the network for src ip
		SSgNet string `ch:"sgnet_s"`
		// name of the network for dst ip
		DSgNet string `ch:"sgnet_d"`
		// agent identifier
		UserAgent string `ch:"agent_id"`
		// time stamps
		Timestamp time.Time `ch:"timestamp"`
	}

	timeFilter string

	// TraceFilter - filters for selecting trace from DB
	TraceFilter struct {
		// traces ids
		TrId []uint32 `ch:"trace_id"`
		// nftables tables names
		Table []string `ch:"table_name"`
		// nftables chains names
		Chain []string `ch:"chain_name"`
		// nftables jump to a target names
		JumpTarget []string `ch:"jump_target"`
		// nftables rules numbers
		RuleHandle []uint64 `ch:"handle"`
		// protocols family
		Family []string `ch:"family"`
		// input network interfaces
		Iifname []string `ch:"ifin"`
		// output network interfaces
		Oifname []string `ch:"ifout"`
		// source mac addresses
		SMacAddr []string `ch:"mac_s"`
		// destination mac addresses
		DMacAddr []string `ch:"mac_d"`
		// source ip addresses
		SAddr []string `ch:"ip_s"`
		// destination ip addresses
		DAddr []string `ch:"ip_d"`
		// source ports
		SPort []uint32 `ch:"sport"`
		// destination ports
		DPort []uint32 `ch:"dport"`
		// names of the security group for src ip
		SSgName []string `ch:"sgname_s"`
		// names of the security group for dst ip
		DSgName []string `ch:"sgname_d"`
		// names of the network for src ip
		SSgNet []string `ch:"sgnet_s"`
		// names of the network for dst ip
		DSgNet []string `ch:"sgnet_d"`
		// lengths of packets
		Length []uint32 `ch:"len"`
		// ip protocols (tcp/udp/icmp/...)
		IpProto []string `ch:"ip_proto"`
		// verdicts of rules
		Verdict []string `ch:"verdict"`
		// rules expressions
		Rule []string `ch:"rule"`
		// time filter
		Time timeFilter `ch:"timestamp"`
		// complete sql Where clauses
		Query string
		// visor agents identifiers
		AgentsIds []string `ch:"agent_id"`
	}

	// NftTablesDB - put nft tables data into DB
	NftTablesDB struct {
		// nftables table name
		TableName string `ch:"table_name"`
		// ndtables table protocols family
		TableFamily string `ch:"table_family"`
		// nftables chain name
		ChainName string `ch:"chain_name"`
		// nftables rule expression
		Rule string `ch:"rule"`
		// nftables table represented as string
		TableStr string `ch:"table_str"`
		// time stamps
		Timestamp time.Time `ch:"timestamp"`
	}

	// FetchNftTablesDB - fetch nft tables fron DB
	FetchNftTablesDB struct {
		// nftables table id
		TableId uint64 `ch:"table_id"`
		// nftables table represented as string
		TableStr string `ch:"table_str"`
		// time stamps
		Timestamp time.Time `ch:"timestamp"`
	}

	NftTablesFilter struct {
		TableId []uint64 `ch:"table_id"`
	}
)

func (t *TraceDB) InitFromTraceModel(msg *model.TraceModel) {
	t.TrId = msg.TrId
	t.Table = msg.Table
	t.Chain = msg.Chain
	t.JumpTarget = msg.JumpTarget
	t.RuleHandle = msg.RuleHandle
	t.Family = msg.Family
	t.Iifname = msg.Iifname
	t.Oifname = msg.Oifname
	t.SMacAddr = msg.SMacAddr
	t.DMacAddr = msg.DMacAddr
	t.SAddr = msg.SAddr
	t.DAddr = msg.DAddr
	t.SPort = msg.SPort
	t.DPort = msg.DPort
	t.SSgName = msg.SSgName
	t.DSgName = msg.DSgName
	t.SSgNet = msg.SSgNet
	t.DSgNet = msg.DSgNet
	t.Length = msg.Length
	t.IpProto = msg.IpProto
	t.Verdict = msg.Verdict
	t.Rule = msg.Rule
	t.UserAgent = msg.UserAgent
	t.Timestamp = time.Now()
}

func (t *TraceDB) ToTraceModel() model.TraceModel {
	return model.TraceModel{
		TrId:       t.TrId,
		Table:      t.Table,
		Chain:      t.Chain,
		JumpTarget: t.JumpTarget,
		RuleHandle: t.RuleHandle,
		Family:     t.Family,
		Iifname:    t.Iifname,
		Oifname:    t.Oifname,
		SMacAddr:   t.SMacAddr,
		DMacAddr:   t.DMacAddr,
		SAddr:      t.SAddr,
		DAddr:      t.DAddr,
		SPort:      t.DPort,
		DPort:      t.DPort,
		SSgName:    t.SSgName,
		DSgName:    t.DSgName,
		SSgNet:     t.SSgNet,
		DSgNet:     t.DSgNet,
		Length:     t.Length,
		IpProto:    t.IpProto,
		Verdict:    t.Verdict,
		Rule:       t.Rule,
		UserAgent:  t.UserAgent,
	}
}

func (t *TraceDB) Columns() (cols []string) {
	t.fieldsIterate(func(_ any, tag string, _ uintptr) {
		cols = append(cols, tag)
	})
	return
}

func (t *TraceDB) FieldTag(field interface{}) string {
	v := reflect.ValueOf(field)
	return t.fieldTags()[v.Pointer()-(uintptr)(unsafe.Pointer(t))]
}

func (t *FetchTraceDB) InitFromModel(msg *model.FetchTraceModel) {
	t.TrId = msg.TrId
	t.TableId = msg.TableId
	t.Table = msg.Table
	t.Chain = msg.Chain
	t.JumpTarget = msg.JumpTarget
	t.RuleHandle = msg.RuleHandle
	t.Rule = msg.Rule
	t.Verdict = msg.Verdict
	t.Iifname = msg.Iifname
	t.Oifname = msg.Oifname
	t.Family = msg.Family
	t.IpProto = msg.IpProto
	t.Length = msg.Length
	t.SMacAddr = msg.SMacAddr
	t.DMacAddr = msg.DMacAddr
	t.SAddr = msg.SAddr
	t.DAddr = msg.DAddr
	t.SPort = msg.SPort
	t.DPort = msg.DPort
	t.SSgName = msg.SSgName
	t.DSgName = msg.DSgName
	t.SSgNet = msg.SSgNet
	t.DSgNet = msg.DSgNet
	t.UserAgent = msg.UserAgent
	t.Timestamp = msg.Timestamp
}

func (t *FetchTraceDB) ToModel() model.FetchTraceModel {
	return model.FetchTraceModel{
		TrId:       t.TrId,
		TableId:    t.TableId,
		Table:      t.Table,
		Chain:      t.Chain,
		JumpTarget: t.JumpTarget,
		RuleHandle: t.RuleHandle,
		Rule:       t.Rule,
		Verdict:    t.Verdict,
		Iifname:    t.Iifname,
		Oifname:    t.Oifname,
		Family:     t.Family,
		IpProto:    t.IpProto,
		Length:     t.Length,
		SMacAddr:   t.SMacAddr,
		DMacAddr:   t.DMacAddr,
		SAddr:      t.SAddr,
		DAddr:      t.DAddr,
		SPort:      t.SPort,
		DPort:      t.DPort,
		SSgName:    t.SSgName,
		DSgName:    t.DSgName,
		SSgNet:     t.SSgNet,
		DSgNet:     t.DSgNet,
		UserAgent:  t.UserAgent,
		Timestamp:  t.Timestamp,
	}
}

func (t *FetchTraceDB) Columns() (cols []string) {
	meta.IterFields(FetchTraceDB{}, "ch", func(_ any, tag string, _ uintptr) {
		cols = append(cols, tag)
	})
	return
}

func (t *FetchNftTablesDB) ToModel() model.FetchNftTableModel {
	return model.FetchNftTableModel{
		TableId:   t.TableId,
		TableStr:  t.TableStr,
		Timestamp: t.Timestamp,
	}
}

func (t *TraceFilter) InitFromModel(msg *model.TraceScopeModel) {
	t.TrId = msg.TrId
	t.Table = msg.Table
	t.Chain = msg.Chain
	t.JumpTarget = msg.JumpTarget
	t.RuleHandle = msg.RuleHandle
	t.Family = msg.Family
	t.Iifname = msg.Iifname
	t.Oifname = msg.Oifname
	t.SMacAddr = msg.SMacAddr
	t.DMacAddr = msg.DMacAddr
	t.SAddr = msg.SAddr
	t.DAddr = msg.DAddr
	t.SPort = msg.SPort
	t.DPort = msg.DPort
	t.SSgName = msg.SSgName
	t.DSgName = msg.DSgName
	t.SSgNet = msg.SSgNet
	t.DSgNet = msg.DSgNet
	t.Length = msg.Length
	t.IpProto = msg.IpProto
	t.Verdict = msg.Verdict
	t.Rule = msg.Rule
	t.Query = msg.Query
	t.AgentsIds = msg.AgentsIds
	if msg.Time != nil && msg.Time.From.Before(msg.Time.To) {
		t.Time = timeFilter(fmt.Sprintf(
			"timestamp BETWEEN '%s' AND '%s'",
			msg.Time.From.Format("2006-01-02 15:04:05"),
			msg.Time.To.Format("2006-01-02 15:04:05"),
		))
	}
}

func (t *TraceFilter) Filters() sq.Sqlizer {
	var flt []sq.Sqlizer
	if t.Query != "" {
		flt = append(flt, sq.Expr(t.Query))
		if len(t.AgentsIds) > 0 {
			flt = append(flt, sq.Eq{meta.GetFieldTag(t, &t.AgentsIds, "ch"): t.AgentsIds})
		}
		if t.Time != "" {
			flt = append(flt, sq.Expr(string(t.Time)))
		}
	} else {
		meta.IterFields(*t, "ch", func(field any, tag string, _ uintptr) {
			v := reflect.ValueOf(field)
			switch v.Kind() {
			case reflect.String:
				switch v := field.(type) {
				case string:
					if v != "" {
						flt = append(flt, sq.Eq{tag: field})
					}
				case timeFilter:
					if v != "" {
						flt = append(flt, sq.Expr(string(v)))
					}
				}
			case reflect.Slice:
				if v.Len() > 0 {
					flt = append(flt, sq.Eq{tag: field})
				}
			default:
				flt = append(flt, sq.Eq{tag: field})
			}
		})
	}

	if len(flt) > 1 {
		return sq.And(flt)
	} else if len(flt) == 1 {
		return flt[0]
	}
	return nil
}

func (t *NftTablesFilter) InitFromScope(scope filter.Scope) {
	if v, ok := scope.(scopes.ScopedById[uint64]); ok {
		t.TableId = v.Ids
	}
}

func (t *NftTablesFilter) Filters() sq.Sqlizer {
	var flt []sq.Sqlizer
	meta.IterFields(*t, "ch", func(field any, tag string, _ uintptr) {
		v := reflect.ValueOf(field)
		switch v.Kind() {
		case reflect.String:
			if v, ok := field.(string); ok && v != "" {
				flt = append(flt, sq.Eq{tag: field})
			}
		case reflect.Slice:
			if v.Len() > 0 {
				flt = append(flt, sq.Eq{tag: field})
			}
		default:
			flt = append(flt, sq.Eq{tag: field})
		}
	})
	if len(flt) > 1 {
		return sq.And(flt)
	} else if len(flt) == 1 {
		return flt[0]
	}
	return nil
}

func (t *TraceDB) fieldsIterate(f func(field any, tag string, offset uintptr)) {
	meta.IterFields(*t, "ch", f)
}

func (t *TraceDB) fieldTags() map[uintptr]string {
	tags := make(map[uintptr]string)
	t.fieldsIterate(func(_ any, tag string, offset uintptr) {
		tags[offset] = tag
	})
	return tags
}
