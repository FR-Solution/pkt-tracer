package nftmonitor

import (
	"fmt"
)

// ErrTableWatcher -
type ErrTableWatcher struct {
	Err error
}

// Error -
func (e ErrTableWatcher) Error() string {
	return fmt.Sprintf("Table-watcher: %v", e.Err)
}

// Cause -
func (e ErrTableWatcher) Cause() error {
	return e.Err
}
