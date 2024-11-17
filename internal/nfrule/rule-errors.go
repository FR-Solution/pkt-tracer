package nfrule

import (
	"errors"
	"fmt"
)

// ErrRule -
type ErrRule struct {
	Err error
}

// Error -
func (e ErrRule) Error() string {
	return fmt.Sprintf("Rule: %v", e.Err)
}

// Cause -
func (e ErrRule) Cause() error {
	return e.Err
}

// Error messages which can be returned by ruler.
var (
	ErrNotFoundRule      = errors.New("rule is not found")
	ErrConvertRuleToJson = errors.New("failed conversion rule to json")
	ErrExpiredTrace      = errors.New("expired trace")
)
