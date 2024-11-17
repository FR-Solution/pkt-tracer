package nfrule

import (
	"sync"
	"time"

	"github.com/wildberries-tech/pkt-tracer/internal/nftables/parser"

	"github.com/H-BF/corlib/pkg/dict"
	nftLib "github.com/google/nftables"
	"github.com/pkg/errors"
)

type (
	RuleEntry struct {
		RuleNative *nftLib.Rule
		RuleStr    string
		removed    bool
		At         time.Time
	}

	RuleEntryKey struct {
		TableName   string
		TableFamily nftLib.TableFamily
		ChainName   string
		Handle      uint64
	}

	// RuleCache - cache to store nftables rules
	RuleCache struct {
		cache     dict.HDict[RuleEntryKey, RuleEntry]
		ttl       time.Duration
		mu        sync.RWMutex
		onceClose sync.Once
		stop      chan struct{}
		stopped   chan struct{}
	}
)

// NewRuleCache - creator for the cache
func NewRuleCache(ttl time.Duration) *RuleCache {
	if ttl < time.Second {
		panic("'RuleCache/ttl' is less than 1s")
	}
	r := &RuleCache{
		ttl:     ttl,
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}

	go r.startCleaner()

	return r
}

func (r *RuleCache) startCleaner() {
	ticker := time.NewTicker(r.ttl)

	defer func() {
		ticker.Stop()
		close(r.stopped)
	}()

	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.clean()
		}
	}
}

func (r *RuleCache) clean() {
	r.mu.Lock()
	defer r.mu.Unlock()

	keys := make([]RuleEntryKey, 0, r.cache.Len())

	r.cache.Iterate(func(k RuleEntryKey, re RuleEntry) bool {
		if re.removed && (time.Since(re.At) >= r.ttl) {
			keys = append(keys, k)
		}
		return true
	})
	r.cache.Del(keys...)
}

// Refresh - update rule cache
func (r *RuleCache) Refresh() error {
	conn, err := nftLib.New()
	if err != nil {
		return errors.WithMessage(err, "failed to create netlink connection")
	}
	defer conn.CloseLasting() //nolint:errcheck

	rules, err := conn.GetAllRules()
	if err != nil {
		return errors.WithMessage(err, "failed to obtain rules from the netfilter")
	}
	t := time.Now()
	for _, rl := range rules {
		strRule, err := (*parser.Rule)(rl).String()
		if err != nil {
			return err
		}

		r.mu.Lock()
		r.cache.Put(
			RuleEntryKey{
				TableName:   rl.Table.Name,
				TableFamily: rl.Table.Family,
				ChainName:   rl.Chain.Name,
				Handle:      rl.Handle},
			RuleEntry{
				RuleNative: rl,
				RuleStr:    strRule,
				At:         t,
			})
		r.mu.Unlock()
	}

	return nil
}

// Get rule by key
func (r *RuleCache) GetRule(k RuleEntryKey) (RuleEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cache.Get(k)
}

// RmRule remove rule by key
func (r *RuleCache) RmRule(k RuleEntryKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache.Del(k)
}

// InsertRule insert rule into cache
func (r *RuleCache) InsertRule(rl RuleEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache.Put(
		RuleEntryKey{
			rl.RuleNative.Table.Name,
			rl.RuleNative.Table.Family,
			rl.RuleNative.Chain.Name,
			rl.RuleNative.Handle},
		rl)
}

// UpdRule update rule in cache
func (r *RuleCache) UpdRule(rl RuleEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache.Put(
		RuleEntryKey{
			rl.RuleNative.Table.Name,
			rl.RuleNative.Table.Family,
			rl.RuleNative.Chain.Name,
			rl.RuleNative.Handle},
		rl)
}

// Close rule cache
func (r *RuleCache) Close() error {
	r.onceClose.Do(func() {
		close(r.stop)
		<-r.stopped
	})
	return nil
}
