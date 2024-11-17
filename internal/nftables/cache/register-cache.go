package cache

import (
	"sync"

	"github.com/H-BF/corlib/pkg/dict"
	"github.com/google/nftables/expr"
)

type (
	RegEntry struct {
		Expr    expr.Any
		ExprStr string
		Any     any
		Len     uint32
		Op      string
	}
	RegCache struct {
		mu    sync.Mutex
		cache dict.HDict[uint32, RegEntry]
	}
)

func NewRegisters() *RegCache {
	return &RegCache{}
}

// GetExpr expression by register
func (r *RegCache) GetExpr(reg uint32) (RegEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cache.Get(reg)
}

// RmExpr remove expression by register
func (r *RegCache) RmExpr(reg uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache.Del(reg)
}

// InsertExpr insert expression into cache by register
func (r *RegCache) InsertExpr(reg uint32, expr RegEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache.Put(reg, expr)
}
