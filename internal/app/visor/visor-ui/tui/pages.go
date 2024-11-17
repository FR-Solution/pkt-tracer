package tui

import (
	"github.com/rivo/tview"
)

// Pages represents a stack of view pages.
type Pages struct {
	*tview.Pages
	*KeyActions
}

func NewPages() *Pages {
	p := Pages{
		Pages:      tview.NewPages(),
		KeyActions: NewKeyActions(),
	}
	return &p
}

// Add - add list of pages.
func (p *Pages) Add(primitives ...Primitive) {
	for _, primitive := range primitives {
		p.AddPage(primitive.Name(), primitive, true, true)
	}
}
