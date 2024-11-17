package tui

import (
	"github.com/rivo/tview"
)

type (
	layoutOptions interface {
		apply(*Layout)
	}
	layoutOptFunc func(*Layout)
	LayoutParams  struct {
		Item       tview.Primitive
		FixedSize  int
		Proportion int
	}
	Layout struct {
		*tview.Flex
		*KeyActions
		PrimitiveName
	}
	GridItems interface {
		getParams() LayoutParams
	}
	gridApplyElemsFunc func() LayoutParams
)

// NewLayout - build new layout from rows and columns and additional options
func NewLayout(name string, elements *tview.Flex, opt ...layoutOptions) *Layout {
	if elements == nil {
		elements = tview.NewFlex()
	}
	layout := &Layout{elements, NewKeyActions(), PrimitiveName(name)}

	for _, o := range opt {
		o.apply(layout)
	}

	return layout
}

// NewRows - new group of rows
func NewRows(rows ...GridItems) *tview.Flex {
	row := tview.NewFlex().SetDirection(tview.FlexRow)
	for _, r := range rows {
		p := r.getParams()
		row = row.AddItem(p.Item, p.FixedSize, p.Proportion, false)
	}
	return row
}

// NewColumns - new group of columns
func NewColumns(cols ...GridItems) *tview.Flex {
	col := tview.NewFlex().SetDirection(tview.FlexColumn)
	for _, c := range cols {
		p := c.getParams()
		col = col.AddItem(p.Item, p.FixedSize, p.Proportion, false)
	}
	return col
}

func (f gridApplyElemsFunc) getParams() LayoutParams {
	return f()
}

func Row(Item tview.Primitive, FixedSize int, Proportion int) GridItems {
	return gridApplyElemsFunc(func() LayoutParams {
		return LayoutParams{Item: Item, FixedSize: FixedSize, Proportion: Proportion}
	})
}

func Column(Item tview.Primitive, FixedSize int, Proportion int) GridItems {
	return gridApplyElemsFunc(func() LayoutParams {
		return LayoutParams{Item: Item, FixedSize: FixedSize, Proportion: Proportion}
	})
}

func (f layoutOptFunc) apply(l *Layout) {
	f(l)
}

// LayoutWithTitle - set title for layout
func LayoutWithTitle(title string) layoutOptions {
	return layoutOptFunc(func(l *Layout) {
		l.SetTitle(title)
	})
}

// LayoutWithBorder - set border for layout
func LayoutWithBorder() layoutOptions {
	return layoutOptFunc(func(l *Layout) {
		l.SetBorder(true)
	})
}

// LayoutWithAlign - set align for layout
func LayoutWithAlign(align int) layoutOptions {
	return layoutOptFunc(func(l *Layout) {
		l.SetTitleAlign(align)
	})
}
