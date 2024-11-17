package encoders

import (
	"fmt"
	"net"
	"testing"

	"github.com/wildberries-tech/pkt-tracer/internal/nftables/cache"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type encodersTestSuite struct {
	suite.Suite
}

func (sui *encodersTestSuite) Test_ByteEncoder() {

	testData := []struct {
		name     string
		expected any
		encode   func() any
	}{
		{
			name:     "1",
			expected: uint64(0),
			encode: func() any {
				return RawBytes([]byte{0}).Uint64()
			},
		},
		{
			name:     "2",
			expected: "",
			encode: func() any {
				return RawBytes([]byte{0}).String()
			},
		},
		{
			name:     "3",
			expected: "0",
			encode: func() any {
				return RawBytes([]byte{0}).Text(10)
			},
		},
		{
			name:     "4",
			expected: "test",
			encode: func() any {
				return RawBytes([]byte("test")).String()
			},
		},

		{
			name:     "5",
			expected: "lo",
			encode: func() any {
				return RawBytes([]byte{108, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}).String()
			},
		},
		{
			name:     "6",
			expected: "27759",
			encode: func() any {
				return RawBytes([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 111}).String()
			},
		},
		{
			name:     "7",
			expected: uint64(27759),
			encode: func() any {
				return RawBytes([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 111}).Uint64()
			},
		},
		{
			name:     "8",
			expected: "27759",
			encode: func() any {
				return RawBytes([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 111}).Text(10)
			},
		},
		{
			name:     "9",
			expected: "6",
			encode: func() any {
				return RawBytes([]byte{6}).String()
			},
		},
		{
			name:     "10",
			expected: "P",
			encode: func() any {
				return RawBytes([]byte{80}).String()
			},
		},
		{
			name:     "11",
			expected: "80",
			encode: func() any {
				return RawBytes([]byte{80}).Text(10)
			},
		},
		{
			name:     "12",
			expected: uint64(80),
			encode: func() any {
				return RawBytes([]byte{80}).Uint64()
			},
		},
		{
			name:     "13",
			expected: "93.184.216.34",
			encode: func() any {
				return RawBytes([]byte{93, 184, 216, 34}).Ip().String()
			},
		},
		{
			name:     "14",
			expected: "10.0.0.0/8",
			encode: func() any {
				return RawBytes([]byte{10}).CIDR().String()
			},
		},
	}
	for _, t := range testData {
		sui.Run(t.name, func() {
			sui.Require().Equal(t.expected, t.encode())
		})
	}
}

func (sui *encodersTestSuite) Test_MultipleExprToString() {
	const (
		tableName = "test"
	)
	testData := []struct {
		name     string
		exprs    nftables.Rule
		preRun   func()
		expected string
	}{
		{
			name: "Expression 1",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
					&expr.Counter{},
					&expr.Log{},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
			},
			expected: "meta l4proto tcp counter packets 0 bytes 0 log accept #handle 0",
		},
		{
			name: "Expression 2",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpNeq,
						Register: 1,
						//Data:     []byte("lo"),
						Data: []byte{108, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					},
					&expr.Immediate{Register: 1, Data: []byte{1}},
					&expr.Meta{Key: expr.MetaKeyNFTRACE, SourceRegister: true, Register: 1},
					&expr.Verdict{
						Kind:  expr.VerdictGoto,
						Chain: "FW-OUT",
					},
				},
			},
			expected: "oifname != lo meta nftrace set 1 goto FW-OUT #handle 0",
		},
		{
			name: "Expression 3",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Payload{
						DestRegister: 1,
						Base:         1,
						Offset:       0,
						Len:          1,
					},
					&expr.Bitwise{
						SourceRegister: 1,
						DestRegister:   1,
						Len:            1,
						Mask:           []byte{240},
						Xor:            []byte{0},
					},
					&expr.Cmp{
						Op:       1,
						Register: 1,
						Data:     []byte{80},
					},
				},
			},
			expected: "ip version != 5 #handle 0",
		},

		{
			name: "Expression 4",
			preRun: func() {
				table := nftables.Table{Name: tableName}
				cache.SetsHolder.InsertSet(
					cache.SetKey{
						TableName: table.Name,
						SetName:   "ipSet",
						SetId:     1,
					},
					&cache.SetEntry{
						Set: nftables.Set{
							Table:   &table,
							Name:    "ipSet",
							KeyType: nftables.TypeIPAddr,
						},
						Elements: []nftables.SetElement{
							{
								Key:         []byte(net.ParseIP("10.34.11.179").To4()),
								IntervalEnd: true,
							},
							{
								Key:         []byte(net.ParseIP("10.34.11.180").To4()),
								IntervalEnd: true,
							},
						},
					},
				)
			},
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       16,
						Len:          4,
					},

					&expr.Lookup{
						SourceRegister: 1,
						SetName:        "ipSet",
						SetID:          1,
					},
				},
			},
			expected: "ip daddr @ipSet #handle 0",
		},
		{
			name: "Expression 5",
			preRun: func() {
				table := nftables.Table{Name: tableName}
				cache.SetsHolder.InsertSet(
					cache.SetKey{
						TableName: table.Name,
						SetName:   "__set0",
					},
					&cache.SetEntry{
						Set: nftables.Set{
							Table:     &table,
							Name:      "__set0",
							Anonymous: true,
							Constant:  true,
							KeyType:   nftables.TypeInetService,
						},
						Elements: []nftables.SetElement{
							{
								Key:         binaryutil.BigEndian.PutUint16(80),
								IntervalEnd: true,
							},
							{
								Key:         binaryutil.BigEndian.PutUint16(443),
								IntervalEnd: true,
							},
						},
					},
				)
			},
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       16,
						Len:          4,
					},
					&expr.Cmp{
						Op:       1,
						Register: 1,
						Data:     []byte{93, 184, 216, 34},
					},
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseTransportHeader,
						Offset:       2,
						Len:          4,
					},
					&expr.Lookup{
						SourceRegister: 1,
						SetName:        "__set0",
					},
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
				},
			},
			expected: "ip daddr != 93.184.216.34 meta l4proto tcp dport {80,443} meta l4proto tcp #handle 0",
		},
		{
			name: "Expression 7",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseTransportHeader,
						Offset:       2,
						Len:          2,
					},
					&expr.Cmp{
						Op:       1,
						Register: 1,
						Data:     []byte{0, 80},
					},
				},
			},
			expected: "th dport != 80 #handle 0",
		},
		{
			name: "Expression 8",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseTransportHeader,
						Offset:       2,
						Len:          2,
					},
					&expr.Cmp{
						Op:       1,
						Register: 1,
						Data:     []byte{0, 80},
					},
				},
			},
			expected: "meta l4proto tcp dport != 80 #handle 0",
		},
		{
			name: "Expression 9",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseTransportHeader,
						Offset:       0,
						Len:          2,
					},
					&expr.Cmp{
						Op:       5,
						Register: 1,
						Data:     []byte{0, 80},
					},
					&expr.Cmp{
						Op:       3,
						Register: 1,
						Data:     []byte{0, 100},
					},
				},
			},
			expected: "meta l4proto tcp sport >= 80 sport <= 100 #handle 0",
		},

		{
			name: "Expression 10",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Immediate{Register: 1, Data: []byte{1}},
					&expr.Meta{Key: expr.MetaKeyNFTRACE, Register: 1, SourceRegister: true},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       16,
						Len:          1,
					},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{10},
					},
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{unix.IPPROTO_UDP},
					},
				},
			},
			expected: "meta nftrace set 1 ip daddr 10.0.0.0/8 meta l4proto udp #handle 0",
		},

		{
			name: "Expression 11",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{unix.IPPROTO_ICMP},
					},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseTransportHeader,
						Offset:       0,
						Len:          1,
					},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{0},
					},
				},
			},
			expected: "meta l4proto icmp type echo-reply #handle 0",
		},

		{
			name: "Expression 11",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Ct{Register: 1},
					&expr.Bitwise{
						SourceRegister: 1,
						DestRegister:   1,
						Len:            4,
						Mask:           []byte{6, 0, 0, 0},
						Xor:            []byte{0, 0, 0, 0},
					},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpNeq,
						Data:     []byte{0, 0, 0, 0},
					},
				},
			},
			expected: "ct state established,related #handle 0",
		},
		{
			name: "Expression 12",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Ct{Register: 1, Key: expr.CtKeyEXPIRATION},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{232, 3, 0, 0},
					},
				},
			},
			expected: "ct expiration 1s #handle 0",
		},
		{
			name: "Expression 13",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{0},
					},
				},
			},
			expected: "ct direction original #handle 0",
		},
		{
			name: "Expression 14",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Ct{Register: 1, Key: expr.CtKeyL3PROTOCOL},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{unix.NFPROTO_IPV4},
					},
				},
			},
			expected: "ct l3proto ipv4 #handle 0",
		},
		{
			name: "Expression 15",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Ct{Register: 1, Key: expr.CtKeyPROTOCOL},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{unix.IPPROTO_TCP},
					},
				},
			},
			expected: "ct protocol tcp #handle 0",
		},
	}
	for _, t := range testData {
		sui.Run(t.name, func() {
			if t.preRun != nil {
				t.preRun()
			}
			str, err := RuleEncode(t.exprs).String()
			sui.Require().NoError(err)
			fmt.Println(str)
			sui.Require().Equal(t.expected, str)
		})
	}
}

func (sui *encodersTestSuite) Test_MultipleExprToJSON() {
	testData := []struct {
		name    string
		exprs   nftables.Rule
		expJson []byte
	}{
		{
			name: "Expression 1",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
					&expr.Counter{},
					&expr.Log{},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
			},
			expJson: []byte(`[{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},{"counter":{"bytes":0,"packets":0}},{"log":null},{"accept":null}]`),
		},
		{
			name: "Expression 2",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpNeq,
						Register: 1,
						//Data:     []byte("lo"),
						Data: []byte{108, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					},
					&expr.Immediate{Register: 1, Data: []byte{1}},
					&expr.Meta{Key: expr.MetaKeyNFTRACE, SourceRegister: true, Register: 1},
					&expr.Verdict{
						Kind:  expr.VerdictGoto,
						Chain: "FW-OUT",
					},
				},
			},
			expJson: []byte(`[{"match":{"op":"!=","left":{"meta":{"key":"oifname"}},"right":"lo"}},{"mangle":{"key":{"meta":{"key":"nftrace"}},"value":1}},{"goto":{"target":"FW-OUT"}}]`),
		},
	}
	for _, t := range testData {
		sui.Run(t.name, func() {
			b, err := EncodeJSON(t.exprs, false)
			sui.Require().NoError(err)
			fmt.Println(string(b))
			sui.Require().Equal(t.expJson, b)
		})
	}
}

func Test_Encoders(t *testing.T) {
	suite.Run(t, new(encodersTestSuite))
}
