package sgnetwork

import (
	"net"
	"sync"
)

type Cache struct {
	mu   sync.Mutex
	fast map[string]*SgNet //by IP(as string)
	slow []*SgNet
}

func (cache *Cache) ensureInit() {
	if cache.fast == nil {
		cache.fast = make(map[string]*SgNet)
	}
}

func (cache *Cache) Clear() {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.slow = nil
	cache.fast = nil
}

func (cache *Cache) Find(ip net.IP) *SgNet {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.ensureInit()
	k := ip.String()
	item, ok := cache.fast[k]
	if !ok {
		for _, n := range cache.slow {
			if n.Net.Contains(ip) {
				item = n
				cache.fast[k] = n
				break
			}
		}
		cache.fast[k] = item
	}
	return item
}

// Init -
func (cache *Cache) Init(sgs []*SgNet) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.slow = sgs
	cache.fast = nil
}
