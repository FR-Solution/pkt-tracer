package nfrule

import (
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"testing"
	"time"

	nfte "github.com/wildberries-tech/pkt-tracer/internal/nftables/encoders"
	"github.com/wildberries-tech/pkt-tracer/internal/nftables/parser"

	"github.com/cespare/xxhash"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type ruleTestSuite struct {
	suite.Suite
}

func (sui *ruleTestSuite) Test_ConvertRuleToJsonString() {
	testData := []struct {
		rule nftables.Rule
		exp  string
	}{
		{
			nftables.Rule{
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
				Handle: 1,
			},
			`[{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},{"counter":{"bytes":0,"packets":0}},{"log":null},{"accept":null}]`,
		},
		{
			nftables.Rule{
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpNeq,
						Register: 1,
						Data:     []byte("lo"),
					},
					&expr.Immediate{Register: 1, Data: []byte{1}},
					&expr.Meta{Key: expr.MetaKeyNFTRACE, SourceRegister: true, Register: 1},
					&expr.Verdict{
						Kind:  expr.VerdictGoto,
						Chain: "FW-OUT",
					},
				},
				Handle: 2,
			},
			`[{"match":{"op":"!=","left":{"meta":{"key":"oifname"}},"right":"lo"}},{"mangle":{"key":{"meta":{"key":"nftrace"}},"value":1}},{"goto":{"target":"FW-OUT"}}]`,
		},
	}
	for _, d := range testData {
		pr := parser.Rule(d.rule)
		r, err := pr.JsonString()
		sui.Require().NoError(err)
		sui.Require().Equal(d.exp, r)
	}
}

func (sui *ruleTestSuite) Test_RuleGetRmMultiThread() {
	testData := []struct {
		rule    nftables.Rule
		exp     string
		expHash uint64
	}{}
	rand.Seed(time.Now().UnixNano())
	for i := 1; i <= 10; i++ {
		randVerdict := expr.VerdictKind(rand.Intn(3) - 1)
		ruleStr := fmt.Sprintf(
			`[{"counter":{"bytes":0,"packets":0}},{"log":null},{%q:null}]`,
			nfte.VerdictKind(randVerdict).String(),
		)
		testData = append(testData, struct {
			rule    nftables.Rule
			exp     string
			expHash uint64
		}{
			nftables.Rule{
				Exprs: []expr.Any{
					&expr.Counter{},
					&expr.Log{},
					&expr.Verdict{
						Kind: randVerdict,
					},
				},
				Table:  &nftables.Table{Name: strconv.Itoa(i), Family: nftables.TableFamilyIPv4},
				Chain:  &nftables.Chain{Name: strconv.Itoa(i + 1)},
				Handle: uint64(i),
			},
			ruleStr,
			xxhash.Sum64String(ruleStr),
		})
	}
	//fill the cache
	rlcache := NewRuleCache(3 * time.Second)
	defer rlcache.Close()

	for _, d := range testData {
		rule := d.rule
		rlStr, err := (*parser.Rule)(&rule).JsonString()
		sui.Require().NoError(err)
		rlcache.InsertRule(RuleEntry{
			RuleNative: &rule,
			RuleStr:    rlStr,
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for _, t := range testData[:5] {
			r, ok := rlcache.GetRule(RuleEntryKey{t.rule.Table.Name, t.rule.Table.Family, t.rule.Chain.Name, t.rule.Handle})
			sui.Require().True(ok)
			rs, err := (*parser.Rule)(r.RuleNative).JsonString()
			sui.Require().NoError(err)
			sui.Require().Equal(t.exp, rs)
			sui.Require().Equal(t.exp, r.RuleStr)
			sui.Require().Equal(t.rule.Handle, r.RuleNative.Handle)
			sui.Require().Equal(t.expHash, xxhash.Sum64String(r.RuleStr))
			rlcache.RmRule(RuleEntryKey{t.rule.Table.Name, t.rule.Table.Family, t.rule.Chain.Name, t.rule.Handle})
			_, ok = rlcache.GetRule(RuleEntryKey{t.rule.Table.Name, t.rule.Table.Family, t.rule.Chain.Name, t.rule.Handle})
			sui.Require().False(ok)
		}
	}()

	go func() {
		defer wg.Done()
		for _, t := range testData[5:] {
			r, ok := rlcache.GetRule(RuleEntryKey{t.rule.Table.Name, t.rule.Table.Family, t.rule.Chain.Name, t.rule.Handle})
			sui.Require().True(ok)
			rs, err := (*parser.Rule)(r.RuleNative).JsonString()
			sui.Require().NoError(err)
			sui.Require().Equal(t.exp, rs)
			sui.Require().Equal(t.exp, r.RuleStr)
			sui.Require().Equal(t.rule.Handle, r.RuleNative.Handle)
			sui.Require().Equal(t.expHash, xxhash.Sum64String(r.RuleStr))
			rlcache.RmRule(RuleEntryKey{t.rule.Table.Name, t.rule.Table.Family, t.rule.Chain.Name, t.rule.Handle})
			_, ok = rlcache.GetRule(RuleEntryKey{t.rule.Table.Name, t.rule.Table.Family, t.rule.Chain.Name, t.rule.Handle})
			sui.Require().False(ok)
		}
	}()

	wg.Wait()
}

func Test_Rule(t *testing.T) {
	suite.Run(t, new(ruleTestSuite))
}
