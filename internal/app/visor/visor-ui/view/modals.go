package view

import (
	"fmt"

	ui "github.com/wildberries-tech/pkt-tracer/internal/app/visor/visor-ui/tui"
)

const (
	exitButtonLabel = "Exit"
	errMsg          = "[red]Error[white]: %s\nPress [yellow]Exit[white] to terminate program, or [yellow]Esc[white] to continue work"
	modalErrName    = "modal-error"
)

type errModal struct {
	*ui.Modal
}

func (a *view) newErrWindow() *errModal {
	m := ui.NewModalWindow(ui.ModalOptions{
		Name:         modalErrName,
		Title:        "Error",
		ButtonsNames: []string{exitButtonLabel},
		ButtonAction: func(buttonIndex int, buttonLabel string) {
			if buttonLabel == exitButtonLabel {
				a.cleanup()
			} else if buttonIndex == -1 {
				a.Page.SwitchToPage(mainLayoutName)
			}
		},
	})

	return &errModal{m}
}

func (e *errModal) ErrMsg(err error) {
	e.SetText(fmt.Sprintf(errMsg, err))
}
