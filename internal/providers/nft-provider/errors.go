package nftprovider

import (
	"fmt"

	"github.com/pkg/errors"
)

// ErrTblProvider -
type ErrTblProvider struct {
	Err error
}

// Error -
func (e ErrTblProvider) Error() string {
	return fmt.Sprintf("table-provider: %v", e.Err)
}

// Cause -
func (e ErrTblProvider) Cause() error {
	return e.Err
}

var ErrCacheMiss = errors.New("table provider cache miss")
