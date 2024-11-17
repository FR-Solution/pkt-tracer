package tui

import (
	"github.com/rivo/tview"
)

// Primitive represents a UI primitive.
type (
	Primitive interface {
		tview.Primitive
		Name() string
	}
	PrimitiveName string
	NextPrimitive func() Primitive
)

// Name - return name of primitive
func (p PrimitiveName) Name() string {
	return string(p)
}

// Helpers...

// NextPrimitive - circular loop through primitives
func NewNextPrimitive(primitives ...Primitive) NextPrimitive {
	l := len(primitives)
	id := 0
	return func() Primitive {
		defer func() { id++ }()
		return primitives[id%l]
	}
}
