package dto

import (
	"context"

	models "github.com/wildberries-tech/pkt-tracer/internal/models/trace"
	proto "github.com/wildberries-tech/pkt-tracer/pkg/api/tracehub"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type (
	TraceDTO struct {
		*proto.Trace
		Md metadata.MD
	}
	FetchTraceDTO struct {
		*proto.FetchTrace
	}
	TraceScopeDTO struct {
		*proto.TraceScope
	}

	NftTableDTO struct {
		*proto.NftTable
	}
	FetchNftTableDTO struct {
		*proto.NftTableResp
	}
)

func (t *NftTableDTO) ToModel() *models.NftTableModel {
	model := &models.NftTableModel{
		TableName:   t.GetTableName(),
		TableFamily: t.GetTableFamily(),
		TableStr:    t.GetTableStr(),
	}
	for _, rl := range t.GetRules() {
		model.Rules = append(model.Rules, &models.NftRule{
			ChainName: rl.GetChainName(),
			Rule:      rl.GetRule(),
		})
	}
	return model
}

func (t *NftTableDTO) ToProto() *proto.NftTable {
	return t.NftTable
}

func (t *NftTableDTO) InitFromProto(msg *proto.NftTable) {
	t.NftTable = msg
}

func (t *NftTableDTO) InitFromModel(md *models.NftTableModel) {
	var rules []*proto.NftRuleInChain
	for _, rl := range md.Rules {
		rules = append(rules, &proto.NftRuleInChain{
			ChainName: rl.ChainName,
			Rule:      rl.Rule,
		})
	}
	t.NftTable = &proto.NftTable{
		TableName:   md.TableName,
		TableFamily: md.TableFamily,
		TableStr:    md.TableStr,
		Rules:       rules,
	}
}

func (ft *TraceScopeDTO) ToModel() *models.TraceScopeModel {
	model := &models.TraceScopeModel{
		TrId:       ft.GetTrId(),
		Table:      ft.GetTable(),
		Chain:      ft.GetChain(),
		JumpTarget: ft.GetJumpTarget(),
		RuleHandle: ft.GetRuleHandle(),
		Family:     ft.GetFamily(),
		Iifname:    ft.GetIifname(),
		Oifname:    ft.GetOifname(),
		SMacAddr:   ft.GetSMacAddr(),
		DMacAddr:   ft.GetDMacAddr(),
		SAddr:      ft.GetSAddr(),
		DAddr:      ft.GetDAddr(),
		SPort:      ft.GetSPort(),
		DPort:      ft.GetDPort(),
		SSgName:    ft.GetSSgName(),
		DSgName:    ft.GetDSgName(),
		SSgNet:     ft.GetSSgNet(),
		DSgNet:     ft.GetDSgNet(),
		Length:     ft.GetLength(),
		IpProto:    ft.GetIpProto(),
		Verdict:    ft.GetVerdict(),
		Rule:       ft.GetRule(),
		FollowMode: ft.GetFollowMode(),
		Query:      ft.GetQuery(),
		AgentsIds:  ft.GetAgentsIds(),
	}

	timeRange := ft.GetTime()
	if timeRange != nil {
		model.Time = &models.TimeRange{
			From: timeRange.From.AsTime(),
			To:   timeRange.To.AsTime(),
		}
	}

	return model
}

func (ft *TraceScopeDTO) ToProto() *proto.TraceScope {
	return ft.TraceScope
}

func (ft *TraceScopeDTO) InitFromProto(msg *proto.TraceScope) {
	ft.TraceScope = msg
}

func (ft *TraceScopeDTO) InitFromModel(md *models.TraceScopeModel) {
	ft.TraceScope = &proto.TraceScope{
		TrId:       md.TrId,
		Table:      md.Table,
		Chain:      md.Chain,
		JumpTarget: md.JumpTarget,
		RuleHandle: md.RuleHandle,
		Family:     md.Family,
		Iifname:    md.Iifname,
		Oifname:    md.Oifname,
		SMacAddr:   md.SMacAddr,
		DMacAddr:   md.DMacAddr,
		SAddr:      md.SAddr,
		DAddr:      md.DAddr,
		SPort:      md.SPort,
		DPort:      md.DPort,
		SSgName:    md.SSgName,
		DSgName:    md.DSgName,
		SSgNet:     md.SSgNet,
		DSgNet:     md.DSgNet,
		Length:     md.Length,
		IpProto:    md.IpProto,
		Verdict:    md.Verdict,
		Rule:       md.Rule,
		FollowMode: md.FollowMode,
		Query:      md.Query,
		AgentsIds:  md.AgentsIds,
	}
	if md.Time != nil {
		ft.Time = &proto.TimeRange{
			From: timestamppb.New(md.Time.From),
			To:   timestamppb.New(md.Time.To),
		}
	}
}

func (t *TraceDTO) ToModel() *models.TraceModel {
	model := &models.TraceModel{
		TrId:       t.GetTrId(),
		Table:      t.GetTable(),
		Chain:      t.GetChain(),
		JumpTarget: t.GetJumpTarget(),
		RuleHandle: t.GetRuleHandle(),
		Family:     t.GetFamily(),
		Iifname:    t.GetIifname(),
		Oifname:    t.GetOifname(),
		SMacAddr:   t.GetSMacAddr(),
		DMacAddr:   t.GetDMacAddr(),
		SAddr:      t.GetSAddr(),
		DAddr:      t.GetDAddr(),
		SPort:      t.GetSPort(),
		DPort:      t.GetDPort(),
		SSgName:    t.GetSSgName(),
		DSgName:    t.GetDSgName(),
		SSgNet:     t.GetSSgNet(),
		DSgNet:     t.GetDSgNet(),
		Length:     t.GetLength(),
		IpProto:    t.GetIpProto(),
		Verdict:    t.GetVerdict(),
		Rule:       t.GetRule(),
	}
	if md := t.Md.Get("user-agent"); len(md) > 0 {
		model.UserAgent = md[0]
	}

	return model
}

func (t *TraceDTO) ToProto() *proto.Trace {
	return t.Trace
}

func (t *TraceDTO) InitFromProto(ctx context.Context, msg *proto.Trace) {
	t.Trace = msg
	t.Md, _ = metadata.FromIncomingContext(ctx)
}

func (t *TraceDTO) InitFromModel(md *models.TraceModel) {
	t.Trace = &proto.Trace{
		TrId:       md.TrId,
		Table:      md.Table,
		Chain:      md.Chain,
		JumpTarget: md.JumpTarget,
		RuleHandle: md.RuleHandle,
		Family:     md.Family,
		Iifname:    md.Iifname,
		Oifname:    md.Oifname,
		SMacAddr:   md.SMacAddr,
		DMacAddr:   md.DMacAddr,
		SAddr:      md.SAddr,
		DAddr:      md.DAddr,
		SPort:      md.SPort,
		DPort:      md.DPort,
		SSgName:    md.SSgName,
		DSgName:    md.DSgName,
		SSgNet:     md.SSgNet,
		DSgNet:     md.DSgNet,
		Length:     md.Length,
		IpProto:    md.IpProto,
		Verdict:    md.Verdict,
		Rule:       md.Rule,
	}
}

func (t *FetchTraceDTO) ToModel() *models.FetchTraceModel {
	return &models.FetchTraceModel{
		TrId:       t.Trace.TrId,
		TableId:    t.TableId,
		Table:      t.Trace.Table,
		Chain:      t.Trace.Chain,
		JumpTarget: t.Trace.JumpTarget,
		RuleHandle: t.Trace.RuleHandle,
		Rule:       t.Trace.Rule,
		Verdict:    t.Trace.Verdict,
		Iifname:    t.Trace.Iifname,
		Oifname:    t.Trace.Oifname,
		Family:     t.Trace.Family,
		IpProto:    t.Trace.IpProto,
		Length:     t.Trace.Length,
		SMacAddr:   t.Trace.SMacAddr,
		DMacAddr:   t.Trace.DMacAddr,
		SAddr:      t.Trace.SAddr,
		DAddr:      t.Trace.DAddr,
		SPort:      t.Trace.SPort,
		DPort:      t.Trace.DPort,
		SSgName:    t.Trace.SSgName,
		DSgName:    t.Trace.DSgName,
		SSgNet:     t.Trace.SSgNet,
		DSgNet:     t.Trace.DSgNet,
		Timestamp:  t.Timestamp.AsTime(),
	}
}

func (t *FetchTraceDTO) ToProto() *proto.FetchTrace {
	return t.FetchTrace
}

func (t *FetchTraceDTO) InitFromProto(msg *proto.FetchTrace) {
	t.FetchTrace = msg
}

func (t *FetchTraceDTO) InitFromModel(md *models.FetchTraceModel) {
	t.FetchTrace = &proto.FetchTrace{
		Trace: &proto.Trace{
			TrId:       md.TrId,
			Table:      md.Table,
			Chain:      md.Chain,
			JumpTarget: md.JumpTarget,
			RuleHandle: md.RuleHandle,
			Family:     md.Family,
			Iifname:    md.Iifname,
			Oifname:    md.Oifname,
			SMacAddr:   md.SMacAddr,
			DMacAddr:   md.DMacAddr,
			SAddr:      md.SAddr,
			DAddr:      md.DAddr,
			SPort:      md.SPort,
			DPort:      md.DPort,
			Length:     md.Length,
			IpProto:    md.IpProto,
			Verdict:    md.Verdict,
			Rule:       md.Rule,
			SSgName:    md.SSgName,
			DSgName:    md.DSgName,
			SSgNet:     md.SSgNet,
			DSgNet:     md.DSgNet,
		},
		TableId:   md.TableId,
		Timestamp: timestamppb.New(md.Timestamp),
	}
}

func (t *FetchNftTableDTO) InitFromModel(md *models.FetchNftTableModel) {
	t.NftTableResp = &proto.NftTableResp{
		TableId:   md.TableId,
		TableStr:  md.TableStr,
		Timestamp: timestamppb.New(md.Timestamp),
	}
}

func (t *FetchNftTableDTO) ToModel() *models.FetchNftTableModel {
	return &models.FetchNftTableModel{
		TableId:   t.TableId,
		TableStr:  t.TableStr,
		Timestamp: t.Timestamp.AsTime(),
	}
}

func (t *FetchNftTableDTO) InitFromProto(msg *proto.NftTableResp) {
	t.NftTableResp = msg
}

func (t *FetchNftTableDTO) ToProto() *proto.NftTableResp {
	return t.NftTableResp
}
