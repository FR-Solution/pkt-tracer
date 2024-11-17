package nftprovider

import (
	"sync"

	"github.com/H-BF/corlib/pkg/dict"
)

type (
	key   = uint64
	tbl   = string
	cache struct {
		dict.HDict[key, tbl]
		mu sync.RWMutex
	}
)

func (c *cache) Get(k key) (v tbl, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.HDict.Get(k)
}

func (c *cache) Put(k key, v tbl) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.HDict.Put(k, v)
}
