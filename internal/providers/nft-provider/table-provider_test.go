package nftprovider

import (
	"context"
	"testing"
	"time"

	proto "github.com/wildberries-tech/pkt-tracer/pkg/api/tracehub"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type tableProviderTestSuite struct {
	suite.Suite
}

func Test_TableProvider(t *testing.T) {
	suite.Run(t, new(tableProviderTestSuite))
}

func (sui *tableProviderTestSuite) Test_FetchTable() {
	var tables = []struct {
		id   uint64
		name string
	}{
		{
			id:   1,
			name: "table1",
		},
		{
			id:   2,
			name: "table2",
		},
		{
			id:   3,
			name: "table3",
		},
	}
	type args struct {
		si time.Duration
	}
	testCases := []struct {
		name string
		args args
		mock func(t *testing.T) Deps
	}{
		{
			name: "Test 1",
			args: args{si: time.Second},
			mock: func(t *testing.T) Deps {
				cli := NewMockClient(t)
				matchReq := func(req *proto.FetchNftTableQry) bool {
					if req != nil && req.Scoped != nil {
						switch sc := req.Scoped.(type) {
						case *proto.FetchNftTableQry_NoScope:
							return true
						case *proto.FetchNftTableQry_ScopedByTableId:
							return assert.NotNil(t, sc.ScopedByTableId) &&
								assert.True(t, len(sc.ScopedByTableId.TableId) > 0)
						}
					}
					return false
				}
				cli.On("FetchNftTable", mock.Anything, mock.MatchedBy(matchReq)).
					Maybe().
					Return(func() (*proto.NftTableList, error) {
						return &proto.NftTableList{
							Tables: []*proto.NftTableResp{
								{
									TableId:   tables[0].id,
									TableStr:  tables[0].name,
									Timestamp: timestamppb.New(time.Now()),
								},
								{
									TableId:   tables[1].id,
									TableStr:  tables[1].name,
									Timestamp: timestamppb.New(time.Now()),
								},
								{
									TableId:   tables[2].id,
									TableStr:  tables[2].name,
									Timestamp: timestamppb.New(time.Now()),
								},
							},
						}, nil
					}())
				return Deps{Cli: cli}
			},
		},
	}
	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			tp := NewTableProvider(tc.mock(sui.T()), tc.args.si)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			errCh := make(chan error)

			go func() {
				errCh <- tp.Run(ctx)
			}()

			err := <-errCh
			close(errCh)
			sui.Require().ErrorIs(context.DeadlineExceeded, err)
			for _, table := range tables {
				tbl, err := tp.GetTableById(table.id)
				sui.Require().NoError(err)
				sui.Require().Equal(table.name, tbl)
			}
			tp.Close()
		})
	}
}
