package flags

import (
	"fmt"
	"testing"

	ch "github.com/wildberries-tech/pkt-tracer/internal/registry/clickhouse"

	"github.com/stretchr/testify/suite"
)

type queryTestSuite struct {
	suite.Suite
	flagToSqlArg map[string]string
}

func (sui *queryTestSuite) SetupTest() {
	obj := &ch.TraceDB{}
	f := Flags{}
	sui.flagToSqlArg = map[string]string{
		f.NameFromTag(&f.TrId):       obj.FieldTag(&obj.TrId),
		f.NameFromTag(&f.Table):      obj.FieldTag(&obj.Table),
		f.NameFromTag(&f.Chain):      obj.FieldTag(&obj.Chain),
		f.NameFromTag(&f.JumpTarget): obj.FieldTag(&obj.JumpTarget),
		f.NameFromTag(&f.RuleHandle): obj.FieldTag(&obj.RuleHandle),
		f.NameFromTag(&f.Family):     obj.FieldTag(&obj.Family),
		f.NameFromTag(&f.Iifname):    obj.FieldTag(&obj.Iifname),
		f.NameFromTag(&f.Oifname):    obj.FieldTag(&obj.Oifname),
		f.NameFromTag(&f.SMacAddr):   obj.FieldTag(&obj.SMacAddr),
		f.NameFromTag(&f.DMacAddr):   obj.FieldTag(&obj.DMacAddr),
		f.NameFromTag(&f.SAddr):      obj.FieldTag(&obj.SAddr),
		f.NameFromTag(&f.DAddr):      obj.FieldTag(&obj.DAddr),
		f.NameFromTag(&f.SPort):      obj.FieldTag(&obj.SPort),
		f.NameFromTag(&f.DPort):      obj.FieldTag(&obj.DPort),
		f.NameFromTag(&f.SSgName):    obj.FieldTag(&obj.SSgName),
		f.NameFromTag(&f.DSgName):    obj.FieldTag(&obj.DSgName),
		f.NameFromTag(&f.SSgNet):     obj.FieldTag(&obj.SSgNet),
		f.NameFromTag(&f.DSgNet):     obj.FieldTag(&obj.DSgNet),
		f.NameFromTag(&f.Length):     obj.FieldTag(&obj.Length),
		f.NameFromTag(&f.IpProto):    obj.FieldTag(&obj.IpProto),
		f.NameFromTag(&f.Verdict):    obj.FieldTag(&obj.Verdict),
	}
}

func Test_Query(t *testing.T) {
	suite.Run(t, new(queryTestSuite))
}

func (sui *queryTestSuite) Test_ValidQuery() {
	f := Flags{}
	type testItem struct {
		name     string
		data     string
		expected string
	}

	testArgs := map[string]struct {
		sqlArg string
		values []string
	}{
		f.NameFromTag(&f.TrId): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.TrId)],
			values: []string{"123", "234", "456", "789"},
		},
		f.NameFromTag(&f.Table): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.Table)],
			values: []string{"'tb1'", "'tb2'", "'tb2'", "'tb3'"},
		},
		f.NameFromTag(&f.Chain): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.Chain)],
			values: []string{"'ch1'", "'ch2'", "'ch3'", "'ch4'"},
		},
		f.NameFromTag(&f.JumpTarget): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.JumpTarget)],
			values: []string{"'jt1'", "'jt2'", "'jt3'", "'jt4'"},
		},
		f.NameFromTag(&f.RuleHandle): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.RuleHandle)],
			values: []string{"1", "2", "3", "4"},
		},
		f.NameFromTag(&f.Family): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.Family)],
			values: []string{"'ip'", "'ip6'", "'arp'", "'inet'"},
		},
		f.NameFromTag(&f.Iifname): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.Iifname)],
			values: []string{"'eth0'", "'eth1'", "'eth2'", "'eth3'"},
		},
		f.NameFromTag(&f.Oifname): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.Oifname)],
			values: []string{"'eth0'", "'eth1'", "'eth2'", "'eth3'"},
		},
		f.NameFromTag(&f.SMacAddr): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.SMacAddr)],
			values: []string{`'00:00:00:00:00:00'`, `'00:00:00:00:00:01'`, `'00:00:00:00:00:02'`, `'00:00:00:00:00:03'`},
		},
		f.NameFromTag(&f.DMacAddr): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.DMacAddr)],
			values: []string{`'00:00:00:00:00:00'`, `'00:00:00:00:00:01'`, `'00:00:00:00:00:02'`, `'00:00:00:00:00:03'`},
		},
		f.NameFromTag(&f.SAddr): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.SAddr)],
			values: []string{`'192.168.0.1'`, `'192.168.0.2'`, `'192.168.0.3'`, `'192.168.0.4'`},
		},
		f.NameFromTag(&f.DAddr): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.DAddr)],
			values: []string{`'192.168.0.1'`, `'192.168.0.2'`, `'192.168.0.3'`, `'192.168.0.4'`},
		},
		f.NameFromTag(&f.SPort): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.SPort)],
			values: []string{"80", "443", "8080", "9650"},
		},
		f.NameFromTag(&f.DPort): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.DPort)],
			values: []string{"80", "443", "8080", "9650"},
		},
		f.NameFromTag(&f.SSgName): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.SSgName)],
			values: []string{"'sg1'", "'no-routed'", "'sg-1'", "'sg-sg'"},
		},
		f.NameFromTag(&f.DSgName): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.DSgName)],
			values: []string{"'sg1'", "'no-routed'", "'sg-1'", "'sg-sg'"},
		},
		f.NameFromTag(&f.SSgNet): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.SSgNet)],
			values: []string{"'net1'", "'net2'", "'net3'", "'net4'"},
		},
		f.NameFromTag(&f.DSgNet): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.DSgNet)],
			values: []string{"'net1'", "'net2'", "'net3'", "'net4'"},
		},
		f.NameFromTag(&f.Length): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.Length)],
			values: []string{"10", "20", "30", "40"},
		},
		f.NameFromTag(&f.IpProto): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.IpProto)],
			values: []string{"'tcp'", "'udp'", "'icmp'", "'igmp'"},
		},
		f.NameFromTag(&f.Verdict): {
			sqlArg: sui.flagToSqlArg[f.NameFromTag(&f.Verdict)],
			values: []string{"'accept'", "'drop'", "'continue'", "'goto'"},
		},
	}

	testData := []testItem{}
	for k, v := range testArgs {
		name := fmt.Sprintf("test valid %s", k)
		testData = append(testData, []testItem{
			{
				name:     name,
				data:     fmt.Sprintf("%s==%s", k, v.values[0]),         //"trid==123",
				expected: fmt.Sprintf("%s = %s", v.sqlArg, v.values[0]), //"trace_id = 123",
			},
			{
				name:     name,
				data:     fmt.Sprintf("%s == %s", k, v.values[0]),       //"trid == 123",
				expected: fmt.Sprintf("%s = %s", v.sqlArg, v.values[0]), //"trace_id = 123",
			},
			{
				name:     name,
				data:     fmt.Sprintf("%s != %s", k, v.values[0]),        //"trid != 123",
				expected: fmt.Sprintf("%s != %s", v.sqlArg, v.values[0]), //"trace_id != 123",
			},
			{
				name:     name,
				data:     fmt.Sprintf("%s > %s", k, v.values[0]),        //"trid > 123",
				expected: fmt.Sprintf("%s > %s", v.sqlArg, v.values[0]), //"trace_id > 123",
			},
			{
				name:     name,
				data:     fmt.Sprintf("%s >= %s", k, v.values[0]),        //"trid >= 123",
				expected: fmt.Sprintf("%s >= %s", v.sqlArg, v.values[0]), //"trace_id >= 123",
			},
			{
				name:     name,
				data:     fmt.Sprintf("%s < %s", k, v.values[0]),        //"trid < 123",
				expected: fmt.Sprintf("%s < %s", v.sqlArg, v.values[0]), // "trace_id < 123",
			},
			{
				name:     name,
				data:     fmt.Sprintf("%s <= %s", k, v.values[0]),        //"trid <= 123",
				expected: fmt.Sprintf("%s <= %s", v.sqlArg, v.values[0]), //"trace_id <= 123",
			},
			{
				name:     name,
				data:     fmt.Sprintf("%s == %s or %s == %s", k, v.values[0], k, v.values[1]),             //"trid == 123 or trid == 123",
				expected: fmt.Sprintf("%s = %s OR %s = %s", v.sqlArg, v.values[0], v.sqlArg, v.values[1]), //"trace_id = 123 OR trace_id = 123",
			},
			{
				name:     name,
				data:     fmt.Sprintf("%s == %s || %s == %s", k, v.values[0], k, v.values[1]),             //"trid == 123 || trid == 123",
				expected: fmt.Sprintf("%s = %s OR %s = %s", v.sqlArg, v.values[0], v.sqlArg, v.values[1]), //"trace_id = 123 OR trace_id = 123",
			},
			{
				name:     name,
				data:     fmt.Sprintf("%s > %s && %s < %s", k, v.values[0], k, v.values[1]),                //"trid > 123 && trid < 123",
				expected: fmt.Sprintf("%s > %s AND %s < %s", v.sqlArg, v.values[0], v.sqlArg, v.values[1]), //"trace_id > 123 AND trace_id < 123",
			},
			{
				name:     name,
				data:     fmt.Sprintf("%s >= %s and %s <= %s", k, v.values[0], k, v.values[1]),               //"trid >= 123 and trid <= 234",
				expected: fmt.Sprintf("%s >= %s AND %s <= %s", v.sqlArg, v.values[0], v.sqlArg, v.values[1]), //"trace_id >= 123 AND trace_id <= 234",
			},
			{
				name:     name,
				data:     fmt.Sprintf("(%s >= %s and %s <= %s)", k, v.values[0], k, v.values[1]),             //"(trid >= 123 and trid <= 234)",
				expected: fmt.Sprintf("%s >= %s AND %s <= %s", v.sqlArg, v.values[0], v.sqlArg, v.values[1]), //"trace_id >= 123 AND trace_id <= 234",
			},
			{
				name:     name,
				data:     fmt.Sprintf("(%s >= %s and %s <= %s) || %s > %s", k, v.values[0], k, v.values[1], k, v.values[2]),                    //"(trid >= 123 and trid <= 234) || trid > 1000",
				expected: fmt.Sprintf("%s >= %s AND %s <= %s OR %s > %s", v.sqlArg, v.values[0], v.sqlArg, v.values[1], v.sqlArg, v.values[2]), //"trace_id >= 123 AND trace_id <= 234 OR trace_id > 1000",
			},
			{
				name:     name,
				data:     fmt.Sprintf("(%s < %s or %s > %s) and %s != %s", k, v.values[0], k, v.values[1], k, v.values[2]),                      //"(trid < 123 or trid > 234) and trid != 1000",
				expected: fmt.Sprintf("(%s < %s OR %s > %s) AND %s != %s", v.sqlArg, v.values[0], v.sqlArg, v.values[1], v.sqlArg, v.values[2]), //"(trace_id < 123 OR trace_id > 234) AND trace_id != 1000",
			},
			{
				name:     name,
				data:     fmt.Sprintf("(%s >= %s and %s <= %s) || (%s >= %s and %s <= %s)", k, v.values[0], k, v.values[1], k, v.values[2], k, v.values[3]),                         //"(trid >= 123 and trid <= 234) || (trid >= 400 and trid <= 500)",
				expected: fmt.Sprintf("%s >= %s AND %s <= %s OR %s >= %s AND %s <= %s", v.sqlArg, v.values[0], v.sqlArg, v.values[1], v.sqlArg, v.values[2], v.sqlArg, v.values[3]), //"trace_id >= 123 AND trace_id <= 234 OR trace_id >= 400 AND trace_id <= 500",
			},
			{
				name:     name,
				data:     fmt.Sprintf("!(%s >= %s and %s <= %s)", k, v.values[0], k, v.values[1]),                  //"!(trid >= 123 and trid <= 234)",
				expected: fmt.Sprintf("NOT (%s >= %s AND %s <= %s)", v.sqlArg, v.values[0], v.sqlArg, v.values[1]), //"NOT (trace_id >= 123 AND trace_id <= 234)",
			},
			{
				name:     name,
				data:     fmt.Sprintf("%s in (%s,%s,%s,%s)", k, v.values[0], v.values[1], v.values[2], v.values[3]),
				expected: fmt.Sprintf("%s IN (%s,%s,%s,%s)", v.sqlArg, v.values[0], v.values[1], v.values[2], v.values[3]),
			},
			{
				name:     name,
				data:     fmt.Sprintf("%s in(%s,%s,%s,%s)", k, v.values[0], v.values[1], v.values[2], v.values[3]),
				expected: fmt.Sprintf("%s IN (%s,%s,%s,%s)", v.sqlArg, v.values[0], v.values[1], v.values[2], v.values[3]),
			},
			{
				name:     name,
				data:     fmt.Sprintf("%s not in (%s,%s,%s,%s)", k, v.values[0], v.values[1], v.values[2], v.values[3]),
				expected: fmt.Sprintf("%s NOT IN (%s,%s,%s,%s)", v.sqlArg, v.values[0], v.values[1], v.values[2], v.values[3]),
			},
			{
				name:     name,
				data:     fmt.Sprintf("%s not in(%s,%s,%s,%s)", k, v.values[0], v.values[1], v.values[2], v.values[3]),
				expected: fmt.Sprintf("%s NOT IN (%s,%s,%s,%s)", v.sqlArg, v.values[0], v.values[1], v.values[2], v.values[3]),
			},
		}...)
	}

	for _, test := range testData {
		sui.Run(test.name, func() {
			parserQuery := NewQueryParser(test.data, sui.flagToSqlArg)
			sqlQuery, err := parserQuery.ToSql()
			sui.Require().NoError(err)
			sui.Require().Equal(test.expected, sqlQuery)
		})
	}
	var expr, expected string
	var i int
	for k, v := range testArgs {
		i++
		expr += fmt.Sprintf("(%s < %s or %s > %s) and !(%s == %s or %s == %s)", k, v.values[0], k, v.values[1], k, v.values[2], k, v.values[3])
		expected += fmt.Sprintf("(%s < %s OR %s > %s) AND NOT (%s = %s OR %s = %s)", v.sqlArg, v.values[0], v.sqlArg, v.values[1], v.sqlArg, v.values[2], v.sqlArg, v.values[3])
		if i < len(testArgs) {
			expr += " and "
			expected += " AND "
		}
	}
	parserQuery := NewQueryParser(expr, sui.flagToSqlArg)
	sqlQuery, err := parserQuery.ToSql()
	sui.Require().NoError(err)
	sui.Require().Equal(expected, sqlQuery)
}

func (sui *queryTestSuite) Test_InvalidQuery() {
	const name = "invalid"
	testData := []struct {
		name string
		expr string
	}{
		{
			name: name,
			expr: "trid=123",
		},
		{
			name: name,
			expr: "trid==123 AND trid==234",
		},
		{
			name: name,
			expr: "trid==123 OR trid==234",
		},
		{
			name: name,
			expr: "table==tb1 OR table==tb2",
		},
		{
			name: name,
			expr: "",
		},
		{
			name: name,
			expr: " ",
		},
		{
			name: name,
			expr: "(",
		},
		{
			name: name,
			expr: ")",
		},
		{
			name: name,
			expr: "()",
		},
		{
			name: name,
			expr: "(trid==123 or trid==234)) and trid != 456",
		},
		{
			name: name,
			expr: "sport==(3 - 2)",
		},
		{
			name: name,
			expr: "sport - dport",
		},
	}
	for _, test := range testData {
		sui.Run(test.name, func() {
			parserQuery := NewQueryParser(test.expr, sui.flagToSqlArg)
			_, err := parserQuery.ToSql()
			sui.Require().Error(err)
		})
	}
}
