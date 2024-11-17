package sgnetwork

import (
	"fmt"

	"github.com/pkg/errors"
)

// ErrSgNw -
type ErrSgNw struct {
	Err error
}

// Error -
func (e ErrSgNw) Error() string {
	return fmt.Sprintf("SgNw: %v", e.Err)
}

// Cause -
func (e ErrSgNw) Cause() error {
	return e.Err
}

var ErrSgMiss = errors.New("sg cache miss")
