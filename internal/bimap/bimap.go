package bimap

type BiMapFace[K1 comparable, K2 comparable, V any] interface {
	Len() int
	Iterate(func(K1, K2, V) bool)
	Clear()
	Insert(K1, K2, V)
	Upd(K1, V) bool
	UpdRev(K2, V) bool
	At(K1) (Tuple[K1, K2, V], bool)
	AtRev(K2) (Tuple[K1, K2, V], bool)
	Rm(K1) *Tuple[K1, K2, V]
	RmRev(K2) *Tuple[K1, K2, V]
}

var _ BiMapFace[int, string, int] = (*BiMap[int, string, int])(nil)

// Tuple is a data structure for storing data in the bimap storage
type Tuple[K1 comparable, K2 comparable, V any] struct {
	K1 K1
	K2 K2
	V  V
}

// BiMap is a double key map structure.
// Both keys are indexed one value in map
type BiMap[K1 comparable, K2 comparable, V any] struct {
	fwd map[K1]*Tuple[K1, K2, V]
	rev map[K2]*Tuple[K1, K2, V]
}

func (bm *BiMap[K1, K2, V]) ensureInit() {
	if bm.fwd == nil {
		bm.fwd = make(map[K1]*Tuple[K1, K2, V])
	}
	if bm.rev == nil {
		bm.rev = make(map[K2]*Tuple[K1, K2, V])
	}
}

// Len - returns the number of key-value pairs in this map.
func (bm *BiMap[K1, K2, V]) Len() int {
	return len(bm.fwd)
}

// Clear - removing all items from map.
func (bm *BiMap[K1, K2, V]) Clear() {
	bm.fwd, bm.rev = nil, nil
}

// Iterate - loops over all the values in this bimap. The loop continues as long
// as the function f returns true.
func (bm *BiMap[K1, K2, V]) Iterate(f func(K1, K2, V) bool) {
	for _, v := range bm.fwd {
		if !f(v.K1, v.K2, v.V) {
			return
		}
	}
}

// Insert - Insert value into map by two keys
func (bm *BiMap[K1, K2, V]) Insert(k1 K1, k2 K2, val V) {
	if oldVal, ok := bm.At(k1); ok {
		delete(bm.rev, oldVal.K2)
	}
	if oldVal, ok := bm.AtRev(k2); ok {
		delete(bm.fwd, oldVal.K1)
	}
	bm.ensureInit()
	v := &Tuple[K1, K2, V]{k1, k2, val}
	bm.fwd[k1] = v
	bm.rev[k2] = v
}

// Upd - Update value into map by key1. Return true if success
func (bm *BiMap[K1, K2, V]) Upd(k K1, v V) bool {
	bm.ensureInit()
	val := bm.fwd[k]
	if val != nil {
		val.V = v
	}
	return val != nil
}

// Upd - Update value into map by key2. Return true if success
func (bm *BiMap[K1, K2, V]) UpdRev(k K2, v V) bool {
	bm.ensureInit()
	val := bm.rev[k]
	if val != nil {
		val.V = v
	}
	return val != nil
}

// Rm - Remove value from map by key1
func (bm *BiMap[K1, K2, V]) Rm(k K1) *Tuple[K1, K2, V] {
	if bm.fwd == nil {
		return nil
	}

	val := bm.fwd[k]
	if val != nil {
		delete(bm.fwd, val.K1)
		delete(bm.rev, val.K2)
	}
	return val
}

// RmRev - Remove value from map by key2
func (bm *BiMap[K1, K2, V]) RmRev(k K2) *Tuple[K1, K2, V] {
	if bm.rev == nil {
		return nil
	}

	val := bm.rev[k]
	if val != nil {
		delete(bm.rev, val.K2)
		delete(bm.fwd, val.K1)
	}
	return val
}

// At - Get item from map by key1.
func (bm *BiMap[K1, K2, V]) At(k K1) (Tuple[K1, K2, V], bool) {
	val := bm.fwd[k]
	if val != nil {
		return *val, true
	}
	return Tuple[K1, K2, V]{}, false
}

// AtRev - Get item from map by key2.
func (bm *BiMap[K1, K2, V]) AtRev(k K2) (Tuple[K1, K2, V], bool) {
	val := bm.rev[k]
	if val != nil {
		return *val, true
	}
	return Tuple[K1, K2, V]{}, false
}
