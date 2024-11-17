package view

import (
	"github.com/gdamore/tcell/v2"
)

func (a *view) helpMenuHandler(evt *tcell.EventKey) *tcell.EventKey {
	a.Page.SwitchToPage(helpLayoutName)
	return evt
}

func (a *view) mainMenuHandler(evt *tcell.EventKey) *tcell.EventKey {
	a.Page.SwitchToPage(mainLayoutName)
	return evt
}

func (a *view) filterMenuHandler(evt *tcell.EventKey) *tcell.EventKey {
	a.Page.SwitchToPage(filtersLayoutName)
	a.sub.Notify(updFiltersInputFields{flt: a.cfg.CmdFlags})
	return evt
}

func (a *view) startTraceHandler(evt *tcell.EventKey) *tcell.EventKey {
	a.handleErr(a.startCapturingTrace())
	return evt
}

func (a *view) stopTraceHandler(evt *tcell.EventKey) *tcell.EventKey {
	a.handleErr(a.stopCapturingTrace())
	return evt
}

func (a *view) togglePanelsHandler(evt *tcell.EventKey) *tcell.EventKey {
	a.SetFocus(a.next())
	return evt
}

func (a *view) exitHandler(evt *tcell.EventKey) *tcell.EventKey {
	a.cleanup()
	return nil
}
