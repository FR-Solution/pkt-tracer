package iface

import (
	"errors"
	"fmt"
)

// ErrIface -
type ErrIface struct {
	Err error
}

// Error -
func (e ErrIface) Error() string {
	return fmt.Sprintf("IFace: %v", e.Err)
}

// Cause -
func (e ErrIface) Cause() error {
	return e.Err
}

var ErrCacheMiss = errors.New("failed to find cache item")
