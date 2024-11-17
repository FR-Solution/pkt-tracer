package nftrace

import (
	"errors"
	"fmt"
)

// ErrCollect -
type (
	ErrCollect struct {
		Err error
	}
	ErrMerge struct {
		Err error
	}
	ErrSend struct {
		Err error
	}
)

// Error -
func (e ErrCollect) Error() string {
	return fmt.Sprintf("Collector: %v", e.Err)
}

// Cause -
func (e ErrCollect) Cause() error {
	return e.Err
}

// Error -
func (e ErrMerge) Error() string {
	return fmt.Sprintf("Merger: %v", e.Err)
}

// Cause -
func (e ErrMerge) Cause() error {
	return e.Err
}

// Error -
func (e ErrSend) Error() string {
	return fmt.Sprintf("Sender: %v", e.Err)
}

// Cause -
func (e ErrSend) Cause() error {
	return e.Err
}

// Error messages which can be returned by trace decoder.
var (
	ErrNoNftaTraceId      = errors.New("NFTA_TRACE_ID not found in message")
	ErrNoNftaTraceType    = errors.New("NFTA_TRACE_TYPE not found in message")
	ErrNoNftaTraceTable   = errors.New("NFTA_TRACE_TABLE not found in message")
	ErrNoNftaTraceChain   = errors.New("NFTA_TRACE_CHAIN not found in message")
	ErrNoNftaTraceVerdict = errors.New("NFTA_TRACE_VERDICT not found in message")
	ErrNoNftaVerdictCode  = errors.New("verdict code not found")
	ErrNoNftaVerdictChain = errors.New("verdict chain not found")

	ErrNftaVerdictEmptyChainError = errors.New("empty verdict chain")

	ErrNftaVerdictParseError = errors.New("failed to parse verdict")

	ErrValidateFailedBreakage = errors.New("incorrect attribute data type or length")

	ErrTraceAttrValidateBreakage = errors.New("incorrect data length")

	ErrTraceAttrValidateMaxTypeExceeded = errors.New("max trace attr type exceeded")

	ErrTraceAttrValidateIncorrectType = errors.New("incorrect received attr type")

	ErrTraceAttrValidateIncorrectTransportHeaderLength = errors.New("incorrect transport header length")

	ErrTraceVerdictValidateBreakage = errors.New("incorrect trace verdict")

	ErrTraceDataNotReady = errors.New("trace not ready")

	ErrTraceSendBufSize = errors.New("invalid size of trace buffer")
)
