package nftrace

import (
	"context"
	"fmt"
	"net"
	"sync"

	nl "github.com/wildberries-tech/pkt-tracer/internal/models/nltrace"
	"github.com/wildberries-tech/pkt-tracer/internal/models/trace"
	"github.com/wildberries-tech/pkt-tracer/internal/nfrule"
	sgnw "github.com/wildberries-tech/pkt-tracer/internal/providers/sg-network"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/queue"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type TraceArray []*NftnlTrace

type MergedTrace struct {
	TrId       uint32
	Table      string
	Chain      string
	JumpTarget string
	RuleHandle uint64
	Family     string
	Iifname    string
	Oifname    string
	SMacAddr   string
	DMacAddr   string
	Saddr      string
	DAddr      string
	Sport      uint16
	Dport      uint16
	Length     uint16
	IpProto    string
	Verdict    string
}

type decision struct {
	dtype uint32
	value uint32
	table string
	chain string
}

func (d decision) getVerdict() string {
	verdict := ""
	switch d.dtype {
	case unix.NFT_TRACETYPE_RULE:
		verdict += "rule::" + d.verdictStr()

	case unix.NFT_TRACETYPE_RETURN:
		verdict += "return::" + d.verdictStr()

	case unix.NFT_TRACETYPE_POLICY:
		verdict += "policy::" + d.verdictStr()
	}
	if d.value != NF_DROP && d.value != NF_ACCEPT {
		verdict += "->"
	}
	return verdict
}

func (d decision) verdictStr() string {
	switch int32(d.value) { //nolint:gosec
	case NF_ACCEPT:
		return "accept"

	case NF_DROP:
		return "drop"

	case NF_STOLEN:
		return "stolen"

	case NF_QUEUE:
		return "queue"

	case NF_REPEAT:
		return "repeat"

	case NF_STOP:
		return "stop"

	case NFT_RETURN:
		return "return"

	case NFT_JUMP:
		return "jump"

	case NFT_GOTO:
		return "goto"

	case NFT_CONTINUE:
		return "continue"

	case NFT_BREAK:
		return "break"
	}

	return "unknown"
}

type traceDecision struct {
	tr            *nl.NetlinkTrace
	verdictCache  map[uint32]bool
	decisionChain []decision
}

func (t *traceDecision) addDecision(d decision) {
	t.verdictCache[d.value] = true
	t.decisionChain = append(t.decisionChain, d)
}

func (t *traceDecision) isReady() bool {
	return t.tr != nil && t.tr.RuleHandle != 0 &&
		(t.verdictCache[NF_DROP] ||
			t.verdictCache[NF_ACCEPT])
}

func (t *traceDecision) iterate(fn func(d decision) bool) {
	for _, v := range t.decisionChain {
		if !fn(v) {
			return
		}
	}
}

type (
	TraceMerger interface {
		Run(ctx context.Context) error
		Reader() <-chan trace.TraceModel
		Close() error
	}
	traceCollector interface {
		Reader() <-chan []nl.NetlinkTrace
	}

	iface interface {
		GetIface(index int) (string, error)
	}

	ruleTracer interface {
		GetRuleForTrace(tr *nl.NetlinkTrace) (nfrule.RuleEntry, error)
	}

	sgNetProviderFace interface {
		GetSGByIP(net.IP) (sgnw.SgNet, error)
	}

	traceMergeImpl struct {
		collector     traceCollector
		ifTracer      iface
		ruler         ruleTracer
		sgNetProvider sgNetProviderFace
		mergeBuf      map[uint32]*traceDecision
		que           queue.FIFO[trace.TraceModel]
		onceRun       sync.Once
		onceClose     sync.Once
		stop          chan struct{}
		stopped       chan struct{}
	}
)

var _ TraceMerger = (*traceMergeImpl)(nil)

func NewTraceMerge(col traceCollector, ift iface, rl ruleTracer, sgc sgNetProviderFace) TraceMerger {
	return &traceMergeImpl{
		collector:     col,
		ifTracer:      ift,
		ruler:         rl,
		sgNetProvider: sgc,
		mergeBuf:      make(map[uint32]*traceDecision),
		que:           queue.NewFIFO[trace.TraceModel](),
		stop:          make(chan struct{}),
	}
}

func (t *traceMergeImpl) Run(ctx context.Context) (err error) {
	var doRun bool
	t.onceRun.Do(func() {
		doRun = true
		t.stopped = make(chan struct{})
	})
	if !doRun {
		return ErrMerge{Err: errors.New("it has been run or closed yet")}
	}

	log := logger.FromContext(ctx).Named("merger")
	log.Info("start")
	defer func() {
		log.Info("stop")
		close(t.stopped)
	}()

	que := t.collector.Reader()

	for {
		select {
		case <-ctx.Done():
			log.Info("will exit cause ctx canceled")
			return ctx.Err()
		case <-t.stop:
			log.Info("will exit cause it has closed")
			return nil
		case traces, ok := <-que:
			if !ok {
				log.Info("will exit cause trace collector queue channel has closed")
				return ErrMerge{Err: errors.New("trace collector queue channel has closed")}
			}
			for _, tr := range traces {
				msg, err := t.prepareTraceMsg(tr)
				if err != nil {
					if errors.Is(err, ErrTraceDataNotReady) ||
						errors.Is(err, nfrule.ErrExpiredTrace) {
						continue //skip error
					}

					return ErrMerge{Err: fmt.Errorf("failed to add trace msg: %v", err)}
				}
				t.que.Put(msg)
			}
		}
	}
}

// Reader return prepared trace from the queue
func (t *traceMergeImpl) Reader() <-chan trace.TraceModel {
	return t.que.Reader()
}

func (t *traceMergeImpl) prepareTraceMsg(tr nl.NetlinkTrace) (msg trace.TraceModel, err error) {
	trD := t.mergeBuf[tr.Id]
	if trD == nil {
		trD = &traceDecision{
			verdictCache: make(map[uint32]bool),
		}
		t.mergeBuf[tr.Id] = trD
	}

	if (tr.Flags&(1<<NFTNL_TRACE_LL_HEADER))|
		(tr.Flags&(1<<NFTNL_TRACE_NETWORK_HEADER)) != 0 {
		trD.tr = &tr
	}

	if tr.Type == unix.NFT_TRACETYPE_RULE && tr.Flags&(1<<NFTNL_TRACE_RULE_HANDLE) != 0 {
		trD.addDecision(decision{
			dtype: unix.NFT_TRACETYPE_RULE,
			value: tr.Verdict,
			table: tr.Table,
			chain: tr.Chain})
	}

	if tr.Type == unix.NFT_TRACETYPE_RETURN && tr.Flags&(1<<NFTNL_TRACE_VERDICT) != 0 {
		trD.addDecision(decision{
			dtype: unix.NFT_TRACETYPE_RETURN,
			value: tr.Verdict,
			table: tr.Table,
			chain: tr.Chain})
	}

	if tr.Type == unix.NFT_TRACETYPE_POLICY && tr.Flags&(1<<NFTNL_TRACE_POLICY) != 0 {
		trD.addDecision(decision{
			dtype: unix.NFT_TRACETYPE_POLICY,
			value: tr.Policy,
			table: tr.Table,
			chain: tr.Chain})
	}

	if !trD.isReady() {
		return msg, ErrTraceDataNotReady
	}
	var verdict string
	trD.iterate(func(d decision) bool {
		verdict += d.getVerdict()
		return true
	})

	re, err := t.ruler.GetRuleForTrace(trD.tr)
	if err != nil {
		return msg, err
	}

	var iifname, oifname string

	if (trD.tr.Flags & (1 << NFTNL_TRACE_IIF)) != 0 {
		iifname, err = t.ifTracer.GetIface(int(trD.tr.Iif))
		if err != nil {
			return msg, errors.WithMessagef(err,
				"failed to find ifname for the ingress traffic by interface id=%d",
				int(trD.tr.Iif))
		}
	}
	if (trD.tr.Flags & (1 << NFTNL_TRACE_OIF)) != 0 {
		oifname, err = t.ifTracer.GetIface(int(trD.tr.Oif))
		if err != nil {
			return msg, errors.WithMessagef(err,
				"failed to find ifname for the egress traffic by interface id=%d",
				int(trD.tr.Oif))
		}
	}
	sgTr := struct {
		sName string
		dName string
		sNet  string
		dNet  string
	}{}

	if sg, err := t.sgNetProvider.GetSGByIP(trD.tr.Nh.SAddr); err != nil {
		if !errors.Is(err, sgnw.ErrSgMiss) {
			return msg, errors.WithMessagef(err, "failed to find security group name for the source IP %s", trD.tr.Nh.SAddr)
		}
	} else {
		sgTr.sName = sg.SgName
		sgTr.sNet = sg.Network.Name
	}

	if sg, err := t.sgNetProvider.GetSGByIP(trD.tr.Nh.DAddr); err != nil {
		if !errors.Is(err, sgnw.ErrSgMiss) {
			return msg, errors.WithMessagef(err, "failed to find security group name for the destination IP %s", trD.tr.Nh.DAddr)
		}
	} else {
		sgTr.dName = sg.SgName
		sgTr.dNet = sg.Network.Name
	}

	msg = trace.TraceModel{
		TrId:       trD.tr.Id,
		Table:      trD.tr.Table,
		Chain:      trD.tr.Chain,
		JumpTarget: trD.tr.JumpTarget,
		RuleHandle: trD.tr.RuleHandle,
		Family:     trD.tr.Family.String(),
		Iifname:    iifname,
		Oifname:    oifname,
		SMacAddr:   trD.tr.Lh.SAddr.String(),
		DMacAddr:   trD.tr.Lh.DAddr.String(),
		SAddr:      trD.tr.Nh.SAddr.String(),
		DAddr:      trD.tr.Nh.DAddr.String(),
		SPort:      uint32(trD.tr.Th.SPort),
		DPort:      uint32(trD.tr.Th.DPort),
		Length:     uint32(trD.tr.Nh.Length),
		IpProto:    trD.tr.Nh.ProtoStr(),
		Verdict:    verdict,
		Rule:       re.RuleStr,
		SSgName:    sgTr.sName,
		DSgName:    sgTr.dName,
		SSgNet:     sgTr.sNet,
		DSgNet:     sgTr.dNet,
	}
	delete(t.mergeBuf, tr.Id)

	return msg, nil
}

// Close merge
func (t *traceMergeImpl) Close() error {
	t.onceClose.Do(func() {
		close(t.stop)
		t.onceRun.Do(func() {})
		if t.stopped != nil {
			<-t.stopped
		}
		_ = t.que.Close()
	})
	return nil
}
