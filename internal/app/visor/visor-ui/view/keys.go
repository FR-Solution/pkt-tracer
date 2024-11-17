package view

import (
	ui "github.com/wildberries-tech/pkt-tracer/internal/app/visor/visor-ui/tui"

	"github.com/gdamore/tcell/v2"
)

const (
	KeyHelp1  tcell.Key = tcell.KeyF1
	KeyHelp2  tcell.Key = ui.KeyHelp
	KeyFilter tcell.Key = ui.KeyF
	KeyExit   tcell.Key = tcell.KeyCtrlC
	KeySave   tcell.Key = tcell.KeyCtrlS
	KeyPause  tcell.Key = ui.KeyP
	KeyStart  tcell.Key = ui.KeyS
)

func (a *view) keyboard(evt *tcell.EventKey) *tcell.EventKey {
	if k, ok := a.HasAction(ui.AsKey(evt)); ok && k.Action != nil {
		return k.Action(evt)
	}
	return evt
}

func (a *view) bindKeys() {
	a.AddActions(ui.NewKeyActionsFromMap(ui.KeyMap{
		tcell.KeyEsc: ui.NewKeyActionWithOpts("mainMenu", a.mainMenuHandler),
		KeyExit:      ui.NewKeyActionWithOpts("exit", a.exitHandler),
	}))
}
