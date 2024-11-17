package iface

import (
	"sync"

	"github.com/wildberries-tech/pkt-tracer/internal/bimap"

	"github.com/pkg/errors"
	link "github.com/vishvananda/netlink"
)

type ifCacheItem struct {
	ifName  string
	ifIndex int
}

type IfaceCache struct {
	cache bimap.BiMap[int, string, ifCacheItem]
	mu    sync.RWMutex
}

func NewCache() *IfaceCache {
	return new(IfaceCache)
}

func (c *IfaceCache) GetItemById(index int) (ifc ifCacheItem, err error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.cache.At(index)
	if !ok {
		return ifc, ErrCacheMiss
	}
	return item.V, nil
}

func (c *IfaceCache) Update(ifc ifCacheItem) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Insert(ifc.ifIndex, ifc.ifName, ifc)
}

func (c *IfaceCache) Reload() error {
	h, err := link.NewHandle()
	if err != nil {
		return errors.WithMessage(err, "failed to create netlink handle to list links")
	}
	defer h.Close()

	links, err := h.LinkList()
	if err != nil {
		return errors.WithMessage(err, "failed to get list of ifaces")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache.Clear()

	for _, link := range links {
		attrs := link.Attrs()
		ifc := ifCacheItem{
			ifName:  attrs.Name,
			ifIndex: attrs.Index,
		}
		c.cache.Insert(ifc.ifIndex, ifc.ifName, ifc)
	}
	return nil
}

func (c *IfaceCache) RmCacheItemByIfName(ifname string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.RmRev(ifname)
}
