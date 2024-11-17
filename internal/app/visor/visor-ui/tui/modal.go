package tui

import "github.com/rivo/tview"

type (
	ButtonHandlerFunc func(buttonIndex int, buttonLabel string)

	Modal struct {
		*tview.Modal
		PrimitiveName
	}
	ModalOptions struct {
		Name         string
		Description  string
		Title        string
		ButtonsNames []string
		ButtonAction ButtonHandlerFunc
	}
)

func NewModalWindow(opt ModalOptions) *Modal {
	m := &Modal{tview.NewModal(), PrimitiveName(opt.Name)}
	if opt.Description != "" {
		m.SetText(opt.Description)
	}
	if len(opt.ButtonsNames) > 0 {
		m.AddButtons(opt.ButtonsNames)
	}

	m.SetBorder(true).SetTitle(opt.Title)
	if opt.ButtonAction != nil {
		m.SetDoneFunc(opt.ButtonAction)
	}
	return m
}
