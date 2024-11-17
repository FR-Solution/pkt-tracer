package scopes

import (
	"github.com/H-BF/corlib/pkg/filter"
	"github.com/google/uuid"
)

// NoScope - no-op scope
func NoScope() filter.Scope {
	return filter.NoScope{}
}

func IDScope[T IdTypes](ids ...T) filter.Scope {
	ret := ScopedById[T]{}
	ret.Ids = append(ret.Ids, ids...)
	return ret
}

type (
	IdTypes interface {
		~int | ~uint |
			~int64 | ~uint64 |
			~int32 | ~uint32 |
			~int16 | ~uint16 |
			~int8 | ~uint8 |
			~string | uuid.UUID
	}
	ScopedById[T IdTypes] struct {
		filter.Scope
		Ids []T
	}
)
