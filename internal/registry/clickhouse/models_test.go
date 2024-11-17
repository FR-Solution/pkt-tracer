package clickhouse

import (
	"testing"
	"time"

	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"
	"github.com/wildberries-tech/pkt-tracer/internal/registry/scopes"

	"github.com/H-BF/corlib/pkg/filter"
	sq "github.com/Masterminds/squirrel"
	"github.com/stretchr/testify/require"
)

func Test_NftablesFilters(t *testing.T) {
	const (
		table = "swarm.nftables"
		sel   = "*"
	)
	testCases := []struct {
		name       string
		scope      filter.Scope
		expFilters sq.Sqlizer
		expSql     string
		expArgs    []interface{}
	}{
		{
			name:   "Empty Scope",
			expSql: "SELECT * FROM swarm.nftables",
		},
		{
			name:   "No Scope",
			scope:  scopes.NoScope(),
			expSql: "SELECT * FROM swarm.nftables",
		},
		{
			name:       "Scope with one Id",
			scope:      scopes.IDScope[uint64](1),
			expSql:     "SELECT * FROM swarm.nftables WHERE table_id IN (?)",
			expFilters: sq.Eq{"table_id": []uint64{1}},
			expArgs:    []interface{}{uint64(1)},
		},
		{
			name:       "Scope with several Ids",
			scope:      scopes.IDScope[uint64](1, 2, 3),
			expSql:     "SELECT * FROM swarm.nftables WHERE table_id IN (?,?,?)",
			expFilters: sq.Eq{"table_id": []uint64{1, 2, 3}},
			expArgs:    []interface{}{uint64(1), uint64(2), uint64(3)},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var filter NftTablesFilter
			filter.InitFromScope(tc.scope)
			filters := filter.Filters()
			sql, args, err := sq.Select(sel).
				From(table).
				Where(filters).
				ToSql()
			require.NoError(t, err)
			require.Equal(t, tc.expSql, sql)
			require.Equal(t, tc.expFilters, filters)
			require.Equal(t, tc.expArgs, args)
		})
	}
}

func Test_TraceFilters(t *testing.T) {
	const (
		sel      = "trace_id, table_id, table_name, chain_name, jump_target, handle, rule, verdict, ifin, ifout, family, ip_proto, len, mac_s, mac_d, ip_s, ip_d, sport, dport, sgname_s, sgname_d, sgnet_s, sgnet_d, agent_id, timestamp"
		table    = "swarm.vu_fetch_trace"
		timeFrom = "2024-09-28 01:11:14"
		timeTo   = "2024-09-28 01:11:17"
	)
	var (
		tables   = []string{"tb1", "tb2"}
		sqlQuery = "dport IN (80,443) AND sport = 80 AND proto IN ('tcp','udp')"
	)
	testCases := []struct {
		name    string
		scope   *model.TraceScopeModel
		expSql  string
		expArgs []interface{}
	}{
		{
			name:   "Empty Filter",
			scope:  &model.TraceScopeModel{},
			expSql: "SELECT " + sel + " FROM swarm.vu_fetch_trace",
		},
		{
			name: "Not Empty Filter without query",
			scope: &model.TraceScopeModel{
				TrId:  []uint32{1},
				Table: tables,
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
			expArgs: []interface{}{uint32(1), tables[0], tables[1]},
			expSql:  "SELECT " + sel + " FROM swarm.vu_fetch_trace WHERE (trace_id IN (?) AND table_name IN (?,?) AND timestamp BETWEEN '" + timeFrom + "' AND '" + timeTo + "')",
		},
		{
			name: "Not Empty Filter with query",
			scope: &model.TraceScopeModel{
				TrId:  []uint32{1},
				Query: sqlQuery,
				Table: tables,
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
			expArgs: []interface{}(nil),
			expSql:  "SELECT " + sel + " FROM swarm.vu_fetch_trace WHERE (" + sqlQuery + " AND timestamp BETWEEN '" + timeFrom + "' AND '" + timeTo + "')",
		},
		{
			name: "Not Empty Filter with query and visor agent ids list",
			scope: &model.TraceScopeModel{
				TrId:      []uint32{1},
				AgentsIds: []string{"tracer1", "tracer2"},
				Query:     sqlQuery,
				Table:     tables,
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
			expArgs: []interface{}{"tracer1", "tracer2"},
			expSql:  "SELECT " + sel + " FROM swarm.vu_fetch_trace WHERE (" + sqlQuery + " AND agent_id IN (?,?) AND timestamp BETWEEN '" + timeFrom + "' AND '" + timeTo + "')",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var filter TraceFilter
			filter.InitFromModel(tc.scope)
			filters := filter.Filters()
			sql, args, err := sq.Select(new(FetchTraceDB).Columns()...).
				From(table).
				Where(filters).
				ToSql()
			require.NoError(t, err)
			require.Equal(t, tc.expSql, sql)
			require.Equal(t, tc.expArgs, args)
		})
	}
}

func Test_FieldTagMethod(t *testing.T) {
	obj := TraceDB{}
	require.Equal(t, "trace_id", obj.FieldTag(&obj.TrId))
	require.Equal(t, "table", obj.FieldTag(&obj.Table))
	require.Equal(t, "chain", obj.FieldTag(&obj.Chain))
	require.Equal(t, "jump_target", obj.FieldTag(&obj.JumpTarget))
	require.Equal(t, "handle", obj.FieldTag(&obj.RuleHandle))
	require.Equal(t, "family", obj.FieldTag(&obj.Family))
	require.Equal(t, "ifin", obj.FieldTag(&obj.Iifname))
	require.Equal(t, "ifout", obj.FieldTag(&obj.Oifname))
	require.Equal(t, "mac_s", obj.FieldTag(&obj.SMacAddr))
	require.Equal(t, "mac_d", obj.FieldTag(&obj.DMacAddr))
	require.Equal(t, "ip_s", obj.FieldTag(&obj.SAddr))
	require.Equal(t, "ip_d", obj.FieldTag(&obj.DAddr))
	require.Equal(t, "sport", obj.FieldTag(&obj.SPort))
	require.Equal(t, "dport", obj.FieldTag(&obj.DPort))
	require.Equal(t, "sgname_s", obj.FieldTag(&obj.SSgName))
	require.Equal(t, "sgname_d", obj.FieldTag(&obj.DSgName))
	require.Equal(t, "sgnet_s", obj.FieldTag(&obj.SSgNet))
	require.Equal(t, "sgnet_d", obj.FieldTag(&obj.DSgNet))
	require.Equal(t, "len", obj.FieldTag(&obj.Length))
	require.Equal(t, "ip_proto", obj.FieldTag(&obj.IpProto))
	require.Equal(t, "verdict", obj.FieldTag(&obj.Verdict))
	require.Equal(t, "rule", obj.FieldTag(&obj.Rule))
	require.Equal(t, "agent_id", obj.FieldTag(&obj.UserAgent))
	require.Equal(t, "timestamp", obj.FieldTag(&obj.Timestamp))
}
