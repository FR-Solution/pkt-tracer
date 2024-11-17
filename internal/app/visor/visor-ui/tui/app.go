package tui

import (
	"context"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// App represents an application.
type App struct {
	*tview.Application
	*KeyActions
	Page *Pages
}

func NewApp() *App {
	a := App{
		Application: tview.NewApplication(),
		Page:        NewPages(),
		KeyActions:  NewKeyActions(),
	}

	a.SetRoot(a.Page, true).SetFocus(a.Page)
	return &a
}

func (a *App) RunWithCtx(ctx context.Context) (err error) {
	errCh := make(chan error)
	go func() {
		defer close(errCh)
		errCh <- a.Run()
	}()
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-errCh:
	}
	return err
}

// QueueUpdate queues up a ui action.
func (a *App) QueueUpdate(f func()) {
	if a.Application == nil {
		return
	}
	go func() {
		a.Application.QueueUpdate(f)
	}()
}

// QueueUpdateDraw queues up a ui action and redraw the ui.
func (a *App) QueueUpdateDraw(f func()) {
	if a.Application == nil {
		return
	}
	go func() {
		a.Application.QueueUpdateDraw(f)
	}()
}

// ----------------------------------------------------------------------------
// Helpers...

// AsKey converts rune to keyboard key.,.
func AsKey(evt *tcell.EventKey) tcell.Key {
	if evt.Key() != tcell.KeyRune {
		return evt.Key()
	}
	key := tcell.Key(evt.Rune())
	if evt.Modifiers() == tcell.ModAlt {
		key = tcell.Key(int16(evt.Rune()) * int16(evt.Modifiers()))
	}
	return key
}

// Stop application if exists
func (a *App) Stop() {
	if a.Application == nil {
		return
	}
	a.Application.Stop()
}
