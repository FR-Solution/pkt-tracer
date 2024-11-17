package registry

import (
	"context"
	"testing"
	"time"

	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"
	ch "github.com/wildberries-tech/pkt-tracer/internal/registry/clickhouse"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type (
	MockDriver struct {
		mock.Mock
	}
)

type FetchTraceDB struct {
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

var expTraces = []model.FetchTraceModel{
	{
		TrId: 123,
		// table id
		TableId: 1,
		// nftables table name
		Table: "tb1",
		// nftables chain name
		Chain: "ch1",
		// nftables jump to a target name
		JumpTarget: "jt1",
		// nftables rule number
		RuleHandle: 5,
		// rule expression
		Rule: "rule",
		// verdict for the rule
		Verdict: "accept",
		// input network interface
		Iifname: "eth0",
		// output network interface
		Oifname: "eth1",
		// protocols family
		Family: "ip",
		// ip protocol (tcp/udp/icmp/...)
		IpProto: "tcp",
		// length packet
		Length: 123,
		// source mac address
		SMacAddr: "00:00:00:00:00:00",
		// destination mac address
		DMacAddr: "00:00:00:00:00:00",
		// source ip address
		SAddr: "192.168.0.1",
		// destination ip address
		DAddr: "192.168.0.2",
		// source port
		SPort: 80,
		// destination port
		DPort: 443,
		// name of the security group for src ip
		SSgName: "sg1",
		// name of the security group for dst ip
		DSgName: "sg2",
		// name of the network for src ip
		SSgNet: "net1",
		// name of the network for dst ip
		DSgNet: "net2",
		// agent identifier
		UserAgent: "agent1",
		// time stamps
		Timestamp: func() time.Time {
			t, _ := time.Parse("2006-01-02 15:04:05", "2024-09-28 01:11:14")
			return t
		}(),
	},
}

// Implementation of mocked method
func (m *MockDriver) Select(ctx context.Context, dest any, query string, args ...any) error {
	switch v := dest.(type) {
	case *[]ch.FetchTraceDB:
		*v = []ch.FetchTraceDB{
			{
				TrId:       expTraces[0].TrId,
				TableId:    expTraces[0].TableId,
				Table:      expTraces[0].Table,
				Chain:      expTraces[0].Chain,
				JumpTarget: expTraces[0].JumpTarget,
				RuleHandle: expTraces[0].RuleHandle,
				Rule:       expTraces[0].Rule,
				Verdict:    expTraces[0].Verdict,
				Iifname:    expTraces[0].Iifname,
				Oifname:    expTraces[0].Oifname,
				Family:     expTraces[0].Family,
				IpProto:    expTraces[0].IpProto,
				Length:     expTraces[0].Length,
				SMacAddr:   expTraces[0].SMacAddr,
				DMacAddr:   expTraces[0].DMacAddr,
				SAddr:      expTraces[0].SAddr,
				DAddr:      expTraces[0].DAddr,
				SPort:      expTraces[0].SPort,
				DPort:      expTraces[0].DPort,
				SSgName:    expTraces[0].SSgName,
				DSgName:    expTraces[0].DSgName,
				SSgNet:     expTraces[0].SSgNet,
				DSgNet:     expTraces[0].DSgNet,
				UserAgent:  expTraces[0].UserAgent,
				Timestamp:  expTraces[0].Timestamp,
			},
		}
	}
	call := m.Called(ctx, dest, query, args)
	return call.Error(0)
}

// Stabs
func (m *MockDriver) Contributors() []string                        { return nil }
func (m *MockDriver) ServerVersion() (*driver.ServerVersion, error) { return nil, nil }
func (m *MockDriver) Query(ctx context.Context, query string, args ...any) (driver.Rows, error) {
	return nil, nil
}
func (m *MockDriver) QueryRow(ctx context.Context, query string, args ...any) driver.Row { return nil }
func (m *MockDriver) PrepareBatch(ctx context.Context, query string, opts ...driver.PrepareBatchOption) (driver.Batch, error) {
	return nil, nil
}
func (m *MockDriver) Exec(ctx context.Context, query string, args ...any) error { return nil }
func (m *MockDriver) AsyncInsert(ctx context.Context, query string, wait bool, args ...any) error {
	return nil
}
func (m *MockDriver) Ping(context.Context) error { return nil }
func (m *MockDriver) Stats() driver.Stats        { return driver.Stats{} }
func (m *MockDriver) Close() error               { return nil }

func Test_FetchTraces(t *testing.T) {
	const (
		sel      = "trace_id, table_id, table_name, chain_name, jump_target, handle, rule, verdict, ifin, ifout, family, ip_proto, len, mac_s, mac_d, ip_s, ip_d, sport, dport, sgname_s, sgname_d, sgnet_s, sgnet_d, agent_id, timestamp"
		table    = "swarm.vu_fetch_trace"
		timeFrom = "2024-09-28 01:11:14"
		timeTo   = "2024-09-28 01:11:17"
	)
	testCases := []struct {
		name  string
		scope *model.TraceScopeModel
		mock  func(t *testing.T) driver.Conn
	}{
		{
			name:  "Empty Filter",
			scope: &model.TraceScopeModel{},
			mock: func(t *testing.T) driver.Conn {
				mockDriver := new(MockDriver)
				queryMatch := mock.MatchedBy(func(query string) bool {
					expQuery := "SELECT " + sel + " FROM " + table
					return assert.Equal(t, expQuery, query)
				})
				mockDriver.On("Select", mock.Anything, mock.Anything, queryMatch, mock.Anything).Maybe().Return(nil)
				return mockDriver
			},
		},
		{
			name: "Filter with Time",
			scope: &model.TraceScopeModel{
				Time: &model.TimeRange{
					From: func() time.Time {
						t, _ := time.Parse("2006-01-02 15:04:05", timeFrom)
						return t
					}(),
					To: func() time.Time {
						t, _ := time.Parse("2006-01-02 15:04:05", timeTo)
						return t
					}(),
				},
			},
			mock: func(t *testing.T) driver.Conn {
				mockDriver := new(MockDriver)
				queryMatch := mock.MatchedBy(func(query string) bool {
					expQuery := "SELECT " + sel + " FROM " + table + " WHERE timestamp BETWEEN '" + timeFrom + "' AND '" + timeTo + "'"
					return assert.Equal(t, expQuery, query)
				})
				mockDriver.On("Select", mock.Anything, mock.Anything, queryMatch, mock.Anything).Maybe().Return(nil)
				return mockDriver
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := clickDbReader{
				reg: &clickDbRegistry{
					db: "swarm",
				},
			}
			r.reg.pool.Store(tc.mock(t), nil)
			res, err := r.FetchTraces(context.Background(), tc.scope)
			require.NoError(t, err)
			require.Equal(t, expTraces, res)
		})
	}

}
