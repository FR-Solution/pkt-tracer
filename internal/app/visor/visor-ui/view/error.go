package view

import "github.com/H-BF/corlib/pkg/patterns/observer"

type (
	errEvent struct {
		err error
		observer.EventType
	}
)

func (a *view) handleErr(err error) {
	if err == nil {
		return
	}
	a.QueueUpdateDraw(func() {
		errModal := a.primitives.At(modalErrName).(*errModal)
		errModal.ErrMsg(err)
		a.Page.SwitchToPage(modalErrName)
		a.sub.Notify(errEvent{err: err})
	})
}
