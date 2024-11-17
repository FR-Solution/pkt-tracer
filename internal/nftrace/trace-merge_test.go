package nftrace

import (
	"testing"

	model "github.com/wildberries-tech/pkt-tracer/internal/models/nltrace"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func Test_DecisionChain(t *testing.T) {
	trD := &traceDecision{
		tr:           &model.NetlinkTrace{RuleHandle: 5},
		verdictCache: make(map[uint32]bool),
	}
	verdict := NFT_GOTO
	trD.addDecision(decision{
		dtype: unix.NFT_TRACETYPE_RULE,
		value: uint32(verdict),
		table: "table1",
		chain: "chain1"})
	require.False(t, trD.isReady())
	verdict = NFT_CONTINUE
	trD.addDecision(decision{
		dtype: unix.NFT_TRACETYPE_RETURN,
		value: uint32(verdict),
		table: "table2",
		chain: "chain2"})
	require.False(t, trD.isReady())
	verdict = NF_ACCEPT
	trD.addDecision(decision{
		dtype: unix.NFT_TRACETYPE_POLICY,
		value: uint32(verdict),
		table: "table3",
		chain: "chain3"})

	require.True(t, trD.isReady())

	var verdictChain string

	trD.iterate(func(d decision) bool {
		verdictChain += d.getVerdict()
		return true
	})

	require.Equal(t, "rule::goto->return::continue->policy::accept", verdictChain)
}
