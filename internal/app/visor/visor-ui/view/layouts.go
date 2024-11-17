//nolint:mnd
package view

import (
	ui "github.com/wildberries-tech/pkt-tracer/internal/app/visor/visor-ui/tui"

	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const (
	mainLayoutName    = "main"
	helpLayoutName    = "help"
	filtersLayoutName = "filters"
	filterHelpDesc    = " Press [yellow]Esc[white] to exit without save, press [yellow]Ctrl-S[white] to save and exit"
)

func (a *view) mainLayout(p panelsMap) ui.Primitive {
	ml := ui.NewLayout(
		mainLayoutName,
		ui.NewRows(
			ui.Row(
				ui.NewColumns(ui.Column(p[panelTraceName], 0, 3), ui.Column(p[panelTblName], 0, 2)), 0, 1,
			),
			ui.Row(
				ui.NewColumns(ui.Column(p[panelHelpInfoName], 0, 1), ui.Column(p[panelSrvInfoName], 0, 1)), 1, 1,
			),
		),
		ui.LayoutWithTitle("Visor"),
		ui.LayoutWithBorder(),
	)
	ml.AddActions(ui.NewKeyActionsFromMap(ui.KeyMap{
		KeyHelp1:     ui.NewKeyActionWithOpts("helpMenu1", a.helpMenuHandler),
		KeyHelp2:     ui.NewKeyActionWithOpts("helpMenu2", a.helpMenuHandler),
		KeyFilter:    ui.NewKeyActionWithOpts("filterMenu", a.filterMenuHandler),
		KeyStart:     ui.NewKeyActionWithOpts("startTrace", a.startTraceHandler),
		KeyPause:     ui.NewKeyActionWithOpts("pauseTrace", a.stopTraceHandler),
		tcell.KeyTab: ui.NewKeyActionWithOpts("togglePanels", a.togglePanelsHandler),
	}))
	ml.SetInputCapture(func(evt *tcell.EventKey) *tcell.EventKey {
		if k, ok := ml.HasAction(ui.AsKey(evt)); ok && k.Action != nil {
			return k.Action(evt)
		}
		return evt
	})
	return ml
}

func (a *view) helpLayout(p panelsMap) ui.Primitive {
	hl := ui.NewLayout(
		helpLayoutName,
		ui.NewRows(
			ui.Row(
				ui.NewColumns(ui.Column(p[panelHelpName], 0, 1)), 0, 1,
			),
			ui.Row(
				ui.NewColumns(ui.Column(p[panelHelpFooterName], 0, 1)), 1, 1,
			),
		),
		ui.LayoutWithTitle("Help"),
		ui.LayoutWithBorder(),
	)
	return hl
}

func (a *view) filtersLayout() ui.Primitive {
	var (
		rows []ui.GridItems
	)

	inputs := newFilterInputs(a.cfg.CmdFlags)
	inputPrimitives := inputs.Primitives()
	for _, inputPrimitive := range inputPrimitives {
		rows = append(rows,
			ui.Row(
				ui.NewColumns(ui.Column(inputPrimitive, 100, 1)), 0, 1,
			),
		)
	}
	rows = append(rows,
		ui.Row(
			ui.NewColumns(ui.Column(ui.NewPanel(ui.PanelOption{
				Name:        "filter-help",
				Description: filterHelpDesc,
				Align:       tview.AlignLeft,
			}), 0, 1)), 1, 1,
		),
	)
	fl := ui.NewLayout(
		filtersLayoutName,
		ui.NewRows(rows...),
		ui.LayoutWithTitle("Filters"),
		ui.LayoutWithBorder(),
	)

	nextPrimitive := ui.NewNextPrimitive(inputPrimitives...)

	fl.AddActions(ui.NewKeyActionsFromMap(ui.KeyMap{
		KeySave: ui.NewKeyActionWithOpts("saveExit", func(evt *tcell.EventKey) *tcell.EventKey {
			a.handleErr(inputs.GetInputValues(&a.cfg.CmdFlags))
			a.handleErr(a.restartCapturingTrace())
			return a.mainMenuHandler(evt)
		}),
		tcell.KeyTab: ui.NewKeyActionWithOpts("toggleFilters", func(evt *tcell.EventKey) *tcell.EventKey {
			a.SetFocus(nextPrimitive())
			return evt
		}),
	}))
	fl.SetInputCapture(func(evt *tcell.EventKey) *tcell.EventKey {
		if k, ok := fl.HasAction(ui.AsKey(evt)); ok && k.Action != nil {
			return k.Action(evt)
		}
		return evt
	})
	a.sub.ObserversAttach(
		observer.NewObserver(
			func(event observer.EventType) {
				if evt, ok := event.(updFiltersInputFields); ok {
					a.handleErr(inputs.updInputFields(evt.flt))
				}
			},
			false,
			updFiltersInputFields{},
		),
	)
	return fl
}
