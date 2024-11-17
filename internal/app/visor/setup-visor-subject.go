package visor

import (
	"sync"

	"github.com/H-BF/corlib/pkg/atomic"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/H-BF/corlib/pkg/signals"
)

type (
	// VisorSubjectClosed -
	VisorSubjectClosed struct{ observer.EventType }
)

// SetupVisorSubject -
func SetupVisorSubject() {
	setupSubjectOfVisorOnce.Do(func() {
		visorSubjectHolder.Store(&subjectOfVisor{
			Subject: observer.NewSubject(),
		}, nil)
		signals.WhenSignalExit(func() error {
			o, _ := visorSubjectHolder.Load()
			o.closed = true
			o.Notify(VisorSubjectClosed{})
			o.DetachAllObservers()
			return nil
		})
	})
}

// VisorSubject -
func VisorSubject() observer.Subject {
	ret, ok := visorSubjectHolder.Load()
	if !ok {
		SetupVisorSubject()
		if ret, ok = visorSubjectHolder.Load(); !ok {
			panic("could't setup visor subject")
		}
	}
	return ret
}

type subjectOfVisor struct {
	closed bool
	observer.Subject
}

// ObserversAttach -
func (a *subjectOfVisor) ObserversAttach(obs ...observer.Observer) {
	if !a.closed {
		a.Subject.ObserversAttach(obs...)
	}
}

var (
	visorSubjectHolder      atomic.Value[*subjectOfVisor]
	setupSubjectOfVisorOnce sync.Once
)
