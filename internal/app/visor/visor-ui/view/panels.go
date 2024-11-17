package view

import (
	"fmt"
	"strconv"

	ui "github.com/wildberries-tech/pkt-tracer/internal/app/visor/visor-ui/tui"
	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"

	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type (
	panelName = string
	panelsMap map[panelName]*ui.Panel

	traceLineEvent struct {
		trace model.FetchTraceModel
		observer.EventType
	}
)

// Panels names
const (
	panelTraceName    = "trace"
	panelTblName      = "tbl"
	panelHelpInfoName = "help-info"
	panelSrvInfoName  = "srv-info"

	panelHelpName       = "help-desc"
	panelHelpFooterName = "help-footer"
)

// Panels content
const (
	SrvColorOK             = "green"
	SrvColorFail           = "red"
	mainHelpInfoFooterDesc = " Press [yellow]F1[white] for help, press [yellow]Ctrl-C[white] to exit"
	mainSrvInfoFooterDesc  = "Server: [%s]%s[white] "

	helpDesc = `Commands:
1) Use [yellow]F1[white] or [yellow]?[white] for help.
2) Use [yellow]Tab[white] to switch between panels.
3) Use [yellow]f[white] to apply filters.
4) Use [yellow]p[white] to pause trace capture.
5) Use [yellow]s[white] to start trace capture.`

	helpFooterDesc = " Press [yellow]Esc[white] to return"
)

type (
	server string
)

func (s server) ok() string {
	return fmt.Sprintf(mainSrvInfoFooterDesc, SrvColorOK, s)
}

func (s server) fail() string {
	return fmt.Sprintf(mainSrvInfoFooterDesc, SrvColorFail, s)
}

func (a *view) newMainPagePanels() (p panelsMap) {
	tracePanel := ui.NewPanel(ui.PanelOption{
		Name:         panelTraceName,
		Title:        "Trace",
		Border:       true,
		AutoScroll:   true,
		ChangeAction: func() { a.Draw() },
	})
	tracePanel.AddActions(ui.NewKeyActionsFromMap(ui.KeyMap{
		tcell.KeyDown: ui.NewKeyActionWithOpts("highlight-down", func(ek *tcell.EventKey) *tcell.EventKey {
			item, ok := tracePanel.CacheLine.Get(int64(tracePanel.HighlightNextLine(true, 2)))
			if !ok {
				item = model.FetchTraceModel{}
			}
			a.sub.Notify(traceLineEvent{trace: item.(model.FetchTraceModel)})
			return ek
		}),
		tcell.KeyUp: ui.NewKeyActionWithOpts("highlight-up", func(ek *tcell.EventKey) *tcell.EventKey {
			item, ok := tracePanel.CacheLine.Get(int64(tracePanel.HighlightNextLine(false, 2)))
			if !ok {
				item = model.FetchTraceModel{}
			}
			a.sub.Notify(traceLineEvent{trace: item.(model.FetchTraceModel)})
			return ek
		}),
	}))
	tracePanel.SetInputCapture(func(evt *tcell.EventKey) *tcell.EventKey {
		if k, ok := tracePanel.HasAction(ui.AsKey(evt)); ok && k.Action != nil {
			return k.Action(evt)
		}
		return evt
	})
	tracePanel.SetMouseCapture(
		func(act tview.MouseAction, evt *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
			if act != tview.MouseLeftClick {
				return act, evt
			}
			lineNum := tracePanel.HighlightLineByMouse(evt)
			item, ok := tracePanel.CacheLine.Get(int64(lineNum - 1))
			if !ok {
				item = model.FetchTraceModel{}
			}
			a.sub.Notify(traceLineEvent{trace: item.(model.FetchTraceModel)})
			return act, evt
		})

	tblPanel := ui.NewPanel(ui.PanelOption{
		Name:       panelTblName,
		Title:      "NFT Tables",
		Border:     true,
		AutoScroll: true,
	})
	helpInfoPanel := ui.NewPanel(ui.PanelOption{
		Name:        panelHelpInfoName,
		Description: mainHelpInfoFooterDesc,
		Align:       tview.AlignLeft,
	})
	srvInfoPanel := ui.NewPanel(ui.PanelOption{
		Name:        panelSrvInfoName,
		Align:       tview.AlignRight,
		Description: server(a.cfg.CmdFlags.ServerUrl).ok(),
	})

	a.sub.ObserversAttach(
		observer.NewObserver(
			func(event observer.EventType) {
				switch evt := event.(type) {
				case errEvent:
					a.QueueUpdateDraw(func() {
						srvInfoPanel.TextView.Clear()
						srvInfoPanel.SetText(server(a.cfg.CmdFlags.ServerUrl).fail())
					})
				case traceLineEvent:
					tblPanel := a.primitives.At(panelTblName).(*ui.Panel)
					if _, ok := tblPanel.CacheLine.Get(int64(evt.trace.TableId)); !ok && evt.trace.TableId > 0 { //nolint:gosec
						tbl, err := a.TblProvider.GetTableById(evt.trace.TableId)
						a.handleErr(err)
						tblPanel.Printf(markLinesWithRule(tbl, evt.trace.TableId)) //nolint:govet
						tblPanel.CacheLine.Put(int64(evt.trace.TableId), tbl)      //nolint:gosec
					}
					tblPanel.Lock()
					defer tblPanel.Unlock()
					tblPanel.Highlight(strconv.FormatUint(evt.trace.TableId^evt.trace.RuleHandle, 10)).ScrollToHighlight()
				}
			},
			false,
			errEvent{},
			traceLineEvent{},
		),
	)

	return panelsMap{
		tracePanel.Name():    tracePanel,
		tblPanel.Name():      tblPanel,
		helpInfoPanel.Name(): helpInfoPanel,
		srvInfoPanel.Name():  srvInfoPanel,
	}
}

func (a *view) newHelpPagePanels() (p panelsMap) {
	helpPanel := ui.NewPanel(ui.PanelOption{
		Name:        panelHelpName,
		Description: helpDesc,
		Border:      true,
	})

	helpFooterPanel := ui.NewPanel(ui.PanelOption{
		Name:        panelHelpFooterName,
		Description: helpFooterDesc,
		Align:       tview.AlignLeft,
	})
	return panelsMap{
		helpPanel.Name():       helpPanel,
		helpFooterPanel.Name(): helpFooterPanel,
	}
}
