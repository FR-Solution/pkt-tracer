package tui

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/H-BF/corlib/pkg/dict"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type (
	cacheLine struct {
		dict.HDict[int64, any]
		mu sync.Mutex
	}
	PanelOption struct {
		Name         string
		Description  string
		Title        string
		Align        int
		Border       bool
		AutoScroll   bool
		Action       ActionHandler
		ChangeAction func()
	}
	Panel struct {
		*tview.TextView
		*KeyActions
		CacheLine cacheLine
		PrimitiveName
		printCount atomic.Int64
	}
)

// NewPanel returns a new textview element.
func NewPanel(opt PanelOption) *Panel {
	p := &Panel{
		TextView:      tview.NewTextView(),
		KeyActions:    NewKeyActions(),
		PrimitiveName: PrimitiveName(opt.Name),
	}
	if opt.Description != "" {
		p.SetText(opt.Description)
	}
	p.SetTextAlign(opt.Align).
		SetDynamicColors(true).
		SetRegions(true)

	if opt.Border {
		p.SetBorder(true).SetTitle(opt.Title)
	}
	if opt.Action != nil {
		p.SetInputCapture(opt.Action)
	}

	p.SetChangedFunc(func() {
		if opt.ChangeAction != nil {
			opt.ChangeAction()
		}
		if opt.AutoScroll {
			if !p.HasFocus() {
				p.Lock()
				defer p.Unlock()
				p.ScrollToEnd()
			}
		}
	})

	return p
}

func (p *Panel) HighlightNextLine(forward bool, lineOffset int) (highlightedLine int) {
	p.Lock()
	defer p.Unlock()
	regions := p.GetHighlights()
	lines := int(p.GetPrintCount())
	highlightedLine = lineOffset % lines
	if len(regions) == 0 {
		if lines > 0 {
			p.Highlight(strconv.Itoa(highlightedLine)).ScrollToHighlight()
		}
	} else {
		highlightedLine, _ = strconv.Atoi(regions[0])
		if forward {
			highlightedLine += 1
		} else {
			highlightedLine = highlightedLine - 1 + lines
		}
		highlightedLine %= lines
		p.Highlight(strconv.Itoa(highlightedLine)).ScrollToHighlight()
	}
	return highlightedLine
}

func (p *Panel) HighlightLineByMouse(event *tcell.EventMouse) (lineNum int) {
	p.Lock()
	defer p.Unlock()
	_, lineNum = event.Position()
	_, _, _, height := p.GetInnerRect() //nolint:dogsled

	if lineNum >= height {
		return -1
	}
	topRow, _ := p.GetScrollOffset()
	if lineNum >= height {
		return -1
	}
	lineNum = topRow + lineNum
	if lineNum > 0 {
		p.Highlight(strconv.Itoa(lineNum - 1)).ScrollToHighlight()
	}
	return
}

func (p *Panel) Printf(msg string, keysAndValues ...interface{}) {
	fmt.Fprintf(p, msg, keysAndValues...)
	p.printCount.Add(1)
}

func (p *Panel) GetPrintCount() int64 {
	return p.printCount.Load()
}

func (p *cacheLine) Put(k int64, v any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.HDict.Put(k, v)
}

func (p *cacheLine) At(k int64) any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.HDict.At(k)
}

func (p *cacheLine) Get(k int64) (v any, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.HDict.Get(k)
}
