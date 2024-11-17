package visor

import (
	"errors"
	"fmt"
)

// ErrVisor -
type ErrVisor struct {
	Err error
}

// Error -
func (e ErrVisor) Error() string {
	return fmt.Sprintf("Visor: %v", e.Err)
}

// Cause -
func (e ErrVisor) Cause() error {
	return e.Err
}

var (
	ErrVisorAlreadyStarted = errors.New("visor has already started")
	ErrVisorAlreadyPaused  = errors.New("visor has already paused")
	ErrVisorStopped        = errors.New("visor has stopped")
	ErrVisorRunOrStopped   = errors.New("visor has already run or stopped")
)
