package nfrule

import (
	"context"
	"fmt"
	"sync"
	"time"

	model "github.com/wildberries-tech/pkt-tracer/internal/models/nltrace"
	"github.com/wildberries-tech/pkt-tracer/internal/nftables/parser"
	"github.com/wildberries-tech/pkt-tracer/internal/nl"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	nftLib "github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// RuleTracer - common interface for the rule trace
type (
	RuleTracer interface {
		Run(ctx context.Context) (err error)
		GetRuleForTrace(tr *model.NetlinkTrace) (re RuleEntry, err error)
		Close() error
	}
	NetlinkWatcher interface {
		Read() chan nl.NlData
	}
	// Deps - dependency
	Deps struct {
		// Adapters
		AgentSubject observer.Subject
		NlWatcher    NetlinkWatcher
	}
)

type (
	ruleTracerImpl struct {
		Deps
		cache     *RuleCache
		onceRun   sync.Once
		onceClose sync.Once
		stop      chan struct{}
		stopped   chan struct{}
	}
	// CountRulerNlErrMemEvent -
	CountRulerNlErrMemEvent struct {
		observer.EventType
	}
)

var _ RuleTracer = (*ruleTracerImpl)(nil)

func NewRuleTrace(d Deps) (rt RuleTracer) {
	const ttl = 3 * time.Second
	return &ruleTracerImpl{
		Deps:  d,
		stop:  make(chan struct{}),
		cache: NewRuleCache(ttl),
	}
}

func (r *ruleTracerImpl) GetRuleForTrace(tr *model.NetlinkTrace) (re RuleEntry, err error) {
	table, chain, handle := tr.Table, tr.Chain, tr.RuleHandle
	re, ok := r.cache.GetRule(RuleEntryKey{table, nftLib.TableFamily(tr.Family), chain, handle})
	if !ok {
		conn, err := nftLib.New()
		if err != nil {
			return re, err
		}
		defer conn.CloseLasting() //nolint:errcheck
		rules, err := conn.GetRules(
			&nftLib.Table{
				Name:   table,
				Family: nftLib.TableFamily(tr.Family)},
			&nftLib.Chain{Name: chain},
		)
		if err != nil {
			return re, err
		}
		var rl *nftLib.Rule
		for _, rule := range rules {
			if rule.Handle == handle {
				rl = rule
				break
			}
		}

		if rl == nil {
			return re, ErrNotFoundRule
		}

		strRule, err := (*parser.Rule)(rl).String()
		if err != nil {
			return re, err
		}
		re = RuleEntry{
			RuleNative: rl,
			RuleStr:    strRule,
			At:         time.Now()}

		r.cache.InsertRule(re)
		return re, nil
	}

	if re.removed || re.At.After(tr.At) ||
		!(re.RuleNative.Table.Name == tr.Table &&
			re.RuleNative.Chain.Name == tr.Chain) {
		return re, ErrExpiredTrace
	}

	return re, nil
}

func (r *ruleTracerImpl) Run(ctx context.Context) (err error) {
	var doRun bool

	r.onceRun.Do(func() {
		doRun = true
		r.stopped = make(chan struct{})
	})
	if !doRun {
		return ErrRule{Err: errors.New("it has been run or closed yet")}
	}

	err = r.cache.Refresh()
	if err != nil {
		return ErrRule{Err: fmt.Errorf("failed to refresh rule cache: %v", err)}
	}

	log := logger.FromContext(ctx).Named("rule-watcher")
	ctx1 := logger.ToContext(ctx, log)

	log.Info("start")
	defer func() {
		log.Info("stop")
		close(r.stopped)
	}()

	for {
		select {
		case <-ctx.Done():
			log.Info("will exit cause ctx canceled")
			return ctx.Err()
		case <-r.stop:
			log.Info("will exit cause it has closed")
			return nil
		case nlData, ok := <-r.Deps.NlWatcher.Read():
			if !ok {
				log.Info("will exit cause rule watcher has already closed")
				return ErrRule{Err: errors.New("rule watcher has already closed")}
			}
			err = nlData.Err
			messages := nlData.Messages

			if err != nil {
				if errors.Is(err, nl.ErrNlMem) {
					r.Deps.AgentSubject.Notify(CountRulerNlErrMemEvent{})
					continue
				}
				if errors.Is(err, nl.ErrNlDataNotReady) ||
					errors.Is(err, nl.ErrNlReadInterrupted) {
					continue
				}

				return ErrRule{Err: errors.WithMessage(err, "failed to rcv nl message")}
			}

			for _, msg := range messages {
				if err = r.handleMsg(ctx1, nl.NetlinkNfMsg(msg)); err != nil {
					return err
				}
			}
		}
	}
}

// handleMsg - handle netlink message
func (r *ruleTracerImpl) handleMsg(ctx context.Context, msg nl.NetlinkNfMsg) error {
	log := logger.FromContext(ctx)
	t := msg.MsgType()
	switch t {
	case unix.NFT_MSG_NEWRULE, unix.NFT_MSG_DELRULE:
		rule := new(parser.Rule)
		err := rule.InitFromMsg(netlink.Message{
			Data: msg.Data,
			Header: netlink.Header{
				Length:   msg.Header.Len,
				Type:     netlink.HeaderType(msg.Header.Type),
				Flags:    netlink.HeaderFlags(msg.Header.Flags),
				Sequence: msg.Header.Seq,
				PID:      msg.Header.Pid,
			},
		})
		if err != nil {
			return errors.WithMessage(err, "failed to fetch rule from netlink message")
		}
		strRule, err := rule.String()
		if err != nil {
			return err
		}

		re := RuleEntry{
			RuleNative: (*nftLib.Rule)(rule),
			RuleStr:    strRule,
			removed:    false,
			At:         time.Now()}

		if t == unix.NFT_MSG_DELRULE {
			re.removed = true
			r.cache.UpdRule(re)
			log.Debugf("removed rule=%d, expr: %s", rule.Handle, strRule)
		} else {
			r.cache.UpdRule(re)
			log.Debugf("added new rule=%d, expr: %s", rule.Handle, strRule)
		}
	}
	return nil
}

// Close rule tracer
func (r *ruleTracerImpl) Close() error {
	r.onceClose.Do(func() {
		close(r.stop)
		r.onceRun.Do(func() {})
		if r.stopped != nil {
			<-r.stopped
		}
		r.cache.Close()
	})
	return nil
}
