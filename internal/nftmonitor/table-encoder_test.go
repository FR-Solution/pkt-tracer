package nftmonitor

import (
	"testing"

	nftLib "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type tblEncodeTestSuite struct {
	suite.Suite
}

func Test_NftTable(t *testing.T) {
	suite.Run(t, new(tblEncodeTestSuite))
}

func (sui *tblEncodeTestSuite) Test_TableEncoder() {
	cases := []struct {
		name    string
		table   TableEntry
		want    string
		wantErr bool
	}{
		{
			name: "Test 1",
			table: TableEntry{
				Table: &nftLib.Table{
					Name:   "table1",
					Family: nftLib.TableFamilyIPv4,
				},
				OrderedSets: SliceT[*SetEntry]{
					slice: []*SetEntry{
						{
							position: 0,
							Set: &nftLib.Set{
								Name:     "portSet",
								KeyType:  nftLib.TypeInetService,
								Constant: true,
								Interval: true,
							},
							OrderedElements: SliceT[ElementEntry]{
								slice: []ElementEntry{
									{
										Elem: nftLib.SetElement{
											Key:         []byte{0},
											IntervalEnd: true,
										},
									},
									{
										Elem: nftLib.SetElement{
											Key:         []byte{80},
											IntervalEnd: false,
										},
									},
									{
										Elem: nftLib.SetElement{
											Key:         []byte{81},
											IntervalEnd: true,
										},
									},
									{
										Elem: nftLib.SetElement{
											Key:         []byte{88},
											IntervalEnd: false,
										},
									},
									{
										Elem: nftLib.SetElement{
											Key:         []byte{89},
											IntervalEnd: true,
										},
									},
								},
							},
						},
					},
				},
				OrderedChains: SliceT[*ChainEntry]{
					slice: []*ChainEntry{
						{
							position: 0,
							Chain: &nftLib.Chain{
								Name:     "chain1",
								Hooknum:  nftLib.ChainHookPostrouting,
								Priority: nftLib.ChainPriorityFilter,
								Type:     nftLib.ChainTypeFilter,
								Policy:   new(nftLib.ChainPolicy),
							},
							OrderedRules: SliceT[*RuleEntry]{
								slice: []*RuleEntry{
									{
										Rule: &nftLib.Rule{
											Handle: 1,
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
									},
									{
										Rule: &nftLib.Rule{
											Handle: 2,
											Exprs: []expr.Any{
												&expr.Immediate{Register: 1, Data: []byte{1}},
												&expr.Meta{Key: expr.MetaKeyNFTRACE, SourceRegister: true, Register: 1},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: `table ip table1 {
	set portSet {
		type inet_service
		flags constant,interval
		elements = { 80,88 }
	}
	chain chain1 {
		type filter hook postrouting priority filter; policy drop;
		meta l4proto tcp counter packets 0 bytes 0 log accept #handle 1
		meta nftrace set 1 #handle 2
	}
}`,
		},
	}
	for _, test := range cases {
		sui.Run(test.name, func() {
			got, err := test.table.String()
			if !test.wantErr {
				sui.Require().NoError(err)
			} else {
				sui.Require().Error(err)
			}
			sui.Require().Equal(test.want, got)
		})
	}
}
