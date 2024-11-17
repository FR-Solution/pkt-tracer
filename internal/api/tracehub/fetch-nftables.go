package tracehub

import (
	"context"

	"github.com/wildberries-tech/pkt-tracer/internal/dto"
	"github.com/wildberries-tech/pkt-tracer/internal/registry/scopes"
	pb "github.com/wildberries-tech/pkt-tracer/pkg/api/tracehub"

	"github.com/H-BF/corlib/pkg/filter"
)

func (srv *thService) FetchNftTable(ctx context.Context, req *pb.FetchNftTableQry) (*pb.NftTableList, error) {
	var scope filter.Scope
	rd, err := srv.reg.Reader(srv.appCtx)
	if err != nil {
		return nil, err
	}
	switch t := req.Scoped.(type) {
	case *pb.FetchNftTableQry_NoScope:
		scope = scopes.NoScope()
	case *pb.FetchNftTableQry_ScopedByTableId:
		scope = scopes.IDScope[uint64](t.ScopedByTableId.TableId...)
	}
	tbls, err := rd.FetchNftTable(srv.appCtx, scope)
	if err != nil {
		return nil, err
	}
	resp := new(pb.NftTableList)

	for _, t := range tbls {
		var tblDto dto.FetchNftTableDTO
		tblDto.InitFromModel(&t)
		resp.Tables = append(resp.Tables, tblDto.ToProto())
	}

	return resp, err
}
