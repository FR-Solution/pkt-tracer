package tracehub

import (
	"sync"

	"github.com/H-BF/corlib/pkg/atomic"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/H-BF/corlib/pkg/signals"
)

type ( //
	// SubjectClosed -
	SubjectClosed struct{ observer.EventType }
)

// SetupSubject -
func SetupSubject() {
	setupSubjectOfServerOnce.Do(func() {
		serverSubjectHolder.Store(&subjectOfServer{
			Subject: observer.NewSubject(),
		}, nil)
		signals.WhenSignalExit(func() error {
			o, _ := serverSubjectHolder.Load()
			o.closed = true
			o.Notify(SubjectClosed{})
			o.DetachAllObservers()
			return nil
		})
	})
}

// ServerSubject -
func ServerSubject() observer.Subject {
	ret, ok := serverSubjectHolder.Load()
	if !ok {
		panic("Need call 'SetupSubject'")
	}
	return ret
}

type subjectOfServer struct {
	closed bool
	observer.Subject
}

// ObserversAttach -
func (a *subjectOfServer) ObserversAttach(obs ...observer.Observer) {
	if !a.closed {
		a.Subject.ObserversAttach(obs...)
	}
}

var (
	serverSubjectHolder      atomic.Value[*subjectOfServer]
	setupSubjectOfServerOnce sync.Once
)
