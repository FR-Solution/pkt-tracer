package encoders

import (
	"github.com/wildberries-tech/pkt-tracer/internal/nftables/cache"

	"github.com/google/nftables"
)

type (
	SetsHolderFace interface {
		GetSet(key cache.SetKey) (*cache.SetEntry, bool)
		InsertSet(key cache.SetKey, val *cache.SetEntry)
	}
	SetsFace interface {
		GetSetByName(t *nftables.Table, name string) (*nftables.Set, error)
		GetSetElements(s *nftables.Set) ([]nftables.SetElement, error)
	}
	Register interface {
		GetExpr(reg uint32) (cache.RegEntry, bool)
		InsertExpr(reg uint32, expr cache.RegEntry)
	}
)
