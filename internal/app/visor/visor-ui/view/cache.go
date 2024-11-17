package view

import (
	"sync"

	"github.com/H-BF/corlib/pkg/dict"
)

type (
	componentName              = string
	componentMap[T any]        map[componentName]T
	cache[K comparable, V any] struct {
		dict.HDict[K, V]
		mu sync.Mutex
	}
	componentCache[T any] struct {
		cache[string, T]
	}
)

func (p *cache[K, V]) Put(k K, v V) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.HDict.Put(k, v)
}

func (p *cache[K, V]) At(k K) V {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.HDict.At(k)
}

func (p *cache[K, V]) Get(k K) (v V, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.HDict.Get(k)
}

func (p *cache[K, V]) Iterate(f func(k K, v V) bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.HDict.Iterate(f)
}

func (p *componentCache[T]) AddPrimitivesFromMap(components componentMap[T]) {
	for k, v := range components {
		p.Put(k, v)
	}
}

func (p *componentCache[T]) GetPrimitivesByNames(names ...string) (res []T) {
	for _, name := range names {
		p.Iterate(func(k string, v T) bool {
			if name == k {
				res = append(res, v)
			}
			return true
		})
	}
	return res
}
