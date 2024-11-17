package cache

import (
	"sync"

	"github.com/H-BF/corlib/pkg/dict"
	"github.com/google/nftables"
)

var SetsHolder SetCache

type (
	SetEntry struct {
		nftables.Set
		Elements []nftables.SetElement
	}

	SetKey struct {
		TableName string
		SetName   string
		SetId     uint32
	}
	SetCache struct {
		mu    sync.Mutex
		cache dict.HDict[SetKey, *SetEntry]
	}
)

// GetSet get ste by key
func (r *SetCache) GetSet(key SetKey) (*SetEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cache.Get(key)
}

// RmSet remove set by key
func (r *SetCache) RmSet(key SetKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache.Del(key)
}

// InsertSet insert set into cache by key
func (r *SetCache) InsertSet(key SetKey, val *SetEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache.Put(key, val)
}
