package tui

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func initInput[T AvailableInputTypes](inputData string) *Input[T] {
	i := NewInput[T](InputOPtions{})
	i.SetText(inputData)
	return i
}

func isTestOK[T AvailableInputTypes](t *testing.T, inputData string, expData any) bool {
	i := initInput[T](inputData)
	actualData, err := i.GetInputValues(",")
	return assert.NoError(t, err) &&
		assert.Equal(t, expData, actualData)
}

func isTestFail[T AvailableInputTypes](t *testing.T, inputData string, expData any) bool {
	i := initInput[T](inputData)
	_, err := i.GetInputValues(",")
	return assert.Error(t, err)
}

func isSetInputsOk[T AvailableInputTypes](t *testing.T, expData string, setData ...any) bool {
	var inData []T
	i := NewInput[T](InputOPtions{})
	for _, d := range setData {
		inData = append(inData, d.(T))
	}
	i.SetInputValues(inData...)
	return assert.Equal(t, expData, i.GetText())
}

func Test_GetInputsValidTests(t *testing.T) {
	type (
		customString  string
		customInt     int
		customInt64   int64
		customUint32  uint32
		customUint64  uint64
		customFloat64 float64
	)

	var testCases = []struct {
		name               string
		inputData          string
		expectedOutputData any
		mock               func(t *testing.T, inputData string, expData any) bool
	}{
		{
			name:               "Valid string input single data",
			inputData:          "eth0",
			expectedOutputData: []string{"eth0"},
			mock:               isTestOK[string],
		},
		{
			name:               "Valid string input multiple string data",
			inputData:          "eth0,eth1,eth2",
			expectedOutputData: []string{"eth0", "eth1", "eth2"},
			mock:               isTestOK[string],
		},
		{
			name:               "Valid string input multiple numeric data",
			inputData:          "1,2,3",
			expectedOutputData: []string{"1", "2", "3"},
			mock:               isTestOK[string],
		},
		{
			name:               "Valid string empty data",
			inputData:          "",
			expectedOutputData: []string(nil),
			mock:               isTestOK[string],
		},

		{
			name:               "Valid int input single data",
			inputData:          "1",
			expectedOutputData: []int{1},
			mock:               isTestOK[int],
		},

		{
			name:               "Valid int input multiple data",
			inputData:          "1,2,3",
			expectedOutputData: []int{1, 2, 3},
			mock:               isTestOK[int],
		},
		{
			name:               "Valid int input empty data",
			inputData:          "",
			expectedOutputData: []int(nil),
			mock:               isTestOK[int],
		},

		{
			name:               "Valid int64 input single data",
			inputData:          "1",
			expectedOutputData: []int64{1},
			mock:               isTestOK[int64],
		},

		{
			name:               "Valid int64 input multiple data",
			inputData:          "1,2,3",
			expectedOutputData: []int64{1, 2, 3},
			mock:               isTestOK[int64],
		},
		{
			name:               "Valid int32 input multiple data",
			inputData:          "1,2,3",
			expectedOutputData: []int32{1, 2, 3},
			mock:               isTestOK[int32],
		},
		{
			name:               "Valid int16 input multiple data",
			inputData:          "1,2,3",
			expectedOutputData: []int16{1, 2, 3},
			mock:               isTestOK[int16],
		},
		{
			name:               "Valid int8 input multiple data",
			inputData:          "1,2,3",
			expectedOutputData: []int8{1, 2, 3},
			mock:               isTestOK[int8],
		},
		{
			name:               "Valid int64 input empty data",
			inputData:          "",
			expectedOutputData: []int64(nil),
			mock:               isTestOK[int64],
		},

		{
			name:               "Valid uint64 input single data",
			inputData:          "1",
			expectedOutputData: []uint64{1},
			mock:               isTestOK[uint64],
		},

		{
			name:               "Valid uint64 input multiple data",
			inputData:          "1,2,3",
			expectedOutputData: []uint64{1, 2, 3},
			mock:               isTestOK[uint64],
		},
		{
			name:               "Valid uint64 input empty data",
			inputData:          "",
			expectedOutputData: []uint64(nil),
			mock:               isTestOK[uint64],
		},

		{
			name:               "Valid uint32 input single data",
			inputData:          "1",
			expectedOutputData: []uint32{1},
			mock:               isTestOK[uint32],
		},

		{
			name:               "Valid uint32 input multiple data",
			inputData:          "1,2,3",
			expectedOutputData: []uint32{1, 2, 3},
			mock:               isTestOK[uint32],
		},
		{
			name:               "Valid uint16 input multiple data",
			inputData:          "1,2,3",
			expectedOutputData: []uint16{1, 2, 3},
			mock:               isTestOK[uint16],
		},
		{
			name:               "Valid uint8 input multiple data",
			inputData:          "1,2,3",
			expectedOutputData: []uint8{1, 2, 3},
			mock:               isTestOK[uint8],
		},
		{
			name:               "Valid uint32 input empty data",
			inputData:          "",
			expectedOutputData: []uint32(nil),
			mock:               isTestOK[uint32],
		},

		{
			name:               "Valid float64 input single data",
			inputData:          "1",
			expectedOutputData: []float64{1},
			mock:               isTestOK[float64],
		},

		{
			name:               "Valid float64 input multiple data",
			inputData:          "1,2,3",
			expectedOutputData: []float64{1, 2, 3},
			mock:               isTestOK[float64],
		},
		{
			name:               "Valid float64 input multiple data with points",
			inputData:          "1.1,2.2,3.3",
			expectedOutputData: []float64{1.1, 2.2, 3.3},
			mock:               isTestOK[float64],
		},
		{
			name:               "Valid float64 input empty data",
			inputData:          "",
			expectedOutputData: []float64(nil),
			mock:               isTestOK[float64],
		},
		{
			name:               "Valid custom string data type",
			inputData:          "1,2,3",
			expectedOutputData: []customString{"1", "2", "3"},
			mock:               isTestOK[customString],
		},
		{
			name:               "Valid custom int data type",
			inputData:          "1,2,3",
			expectedOutputData: []customInt{1, 2, 3},
			mock:               isTestOK[customInt],
		},
		{
			name:               "Valid custom int64 data type",
			inputData:          "1,2,3",
			expectedOutputData: []customInt64{1, 2, 3},
			mock:               isTestOK[customInt64],
		},
		{
			name:               "Valid custom uint64 data type",
			inputData:          "1,2,3",
			expectedOutputData: []customUint64{1, 2, 3},
			mock:               isTestOK[customUint64],
		},
		{
			name:               "Valid custom uint32 data type",
			inputData:          "1,2,3",
			expectedOutputData: []customUint32{1, 2, 3},
			mock:               isTestOK[customUint32],
		},
		{
			name:               "Valid custom float64 data type",
			inputData:          "1,2,3",
			expectedOutputData: []customFloat64{1, 2, 3},
			mock:               isTestOK[customFloat64],
		},
		{
			name:               "Valid time duration data type",
			inputData:          "1s",
			expectedOutputData: []time.Duration{time.Second},
			mock:               isTestOK[time.Duration],
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.True(t, tc.mock(t, tc.inputData, tc.expectedOutputData))
		})
	}
}

func Test_GetInputsInValidTests(t *testing.T) {
	var testCases = []struct {
		name               string
		inputData          string
		expectedOutputData any
		mock               func(t *testing.T, inputData string, expData any) bool
	}{
		{
			name:      "Invalid input int with string",
			inputData: "eth0",
			mock:      isTestFail[int],
		},
		{
			name:      "Invalid input int with point after number",
			inputData: "1.",
			mock:      isTestFail[int],
		},
		{
			name:      "Invalid input int with point between number",
			inputData: "1.1",
			mock:      isTestFail[int],
		},
		{
			name:      "Invalid input int with point before number",
			inputData: ".1",
			mock:      isTestFail[int],
		},
		{
			name:      "Invalid input float64 with string",
			inputData: "eth0",
			mock:      isTestFail[float64],
		},

		{
			name:      "Invalid string data with single comma after",
			inputData: "1,",
			mock:      isTestFail[string],
		},
		{
			name:      "Invalid string data with single comma before",
			inputData: ",1",
			mock:      isTestFail[string],
		},
		{
			name:      "Invalid int data with single comma after",
			inputData: "1,",
			mock:      isTestFail[int],
		},
		{
			name:      "Invalid int data with single comma before",
			inputData: ",1",
			mock:      isTestFail[int],
		},
		{
			name:      "Invalid int64 data with single comma after",
			inputData: "1,",
			mock:      isTestFail[int64],
		},
		{
			name:      "Invalid int64 data with single comma before",
			inputData: ",1",
			mock:      isTestFail[int64],
		},
		{
			name:      "Invalid uint64 data with single comma after",
			inputData: "1,",
			mock:      isTestFail[uint64],
		},
		{
			name:      "Invalid uint64 data with single comma before",
			inputData: ",1",
			mock:      isTestFail[uint64],
		},
		{
			name:      "Invalid uint32 data with single comma after",
			inputData: "1,",
			mock:      isTestFail[uint32],
		},
		{
			name:      "Invalid uint32 data with single comma before",
			inputData: ",1",
			mock:      isTestFail[uint32],
		},
		{
			name:      "Invalid float64 data with single comma after",
			inputData: "1,",
			mock:      isTestFail[float64],
		},
		{
			name:      "Invalid float64 data with single comma before",
			inputData: ",1",
			mock:      isTestFail[float64],
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.True(t, tc.mock(t, tc.inputData, tc.expectedOutputData))
		})
	}
}

func Test_SetInputsValidTests(t *testing.T) {
	type (
		customString  string
		customInt     int
		customInt64   int64
		customUint32  uint32
		customUint64  uint64
		customFloat64 float64
	)
	var testCases = []struct {
		name      string
		inputData []any
		expData   string
		mock      func(t *testing.T, expData string, setData ...any) bool
	}{
		{
			name:      "Valid string input single data",
			inputData: []any{"eth0"},
			expData:   "eth0",
			mock:      isSetInputsOk[string],
		},
		{
			name:      "Valid string input multiple string data",
			inputData: []any{"eth0", "eth1", "eth2"},
			expData:   "eth0,eth1,eth2",
			mock:      isSetInputsOk[string],
		},
		{
			name:      "Valid string empty data",
			inputData: []any(nil),
			expData:   "",
			mock:      isSetInputsOk[string],
		},
		{
			name:      "Valid int input single data",
			inputData: []any{int(1)},
			expData:   "1",
			mock:      isSetInputsOk[int],
		},
		{
			name:      "Valid int input negative single data",
			inputData: []any{int(-1)},
			expData:   "-1",
			mock:      isSetInputsOk[int],
		},
		{
			name:      "Valid int input multiple data",
			inputData: []any{1, 2, 3},
			expData:   "1,2,3",
			mock:      isSetInputsOk[int],
		},
		{
			name:      "Valid int input empty data",
			inputData: []any(nil),
			expData:   "",
			mock:      isSetInputsOk[int],
		},
		{
			name:      "Valid int64 input multiple data",
			expData:   "1,2,3",
			inputData: []any{int64(1), int64(2), int64(3)},
			mock:      isSetInputsOk[int64],
		},
		{
			name:      "Valid int32 input multiple data",
			expData:   "1,2,3",
			inputData: []any{int32(1), int32(2), int32(3)},
			mock:      isSetInputsOk[int32],
		},
		{
			name:      "Valid int16 input multiple data",
			expData:   "1,2,3",
			inputData: []any{int16(1), int16(2), int16(3)},
			mock:      isSetInputsOk[int16],
		},
		{
			name:      "Valid int8 input multiple data",
			expData:   "1,2,3",
			inputData: []any{int8(1), int8(2), int8(3)},
			mock:      isSetInputsOk[int8],
		},
		{
			name:      "Valid uint64 input multiple data",
			expData:   "1,2,3",
			inputData: []any{uint64(1), uint64(2), uint64(3)},
			mock:      isSetInputsOk[uint64],
		},
		{
			name:      "Valid uint32 input single data",
			expData:   "1",
			inputData: []any{uint32(1)},
			mock:      isSetInputsOk[uint32],
		},
		{
			name:      "Valid uint32 input multiple data",
			expData:   "1,2,3",
			inputData: []any{uint32(1), uint32(2), uint32(3)},
			mock:      isSetInputsOk[uint32],
		},
		{
			name:      "Valid uint16 input multiple data",
			expData:   "1,2,3",
			inputData: []any{uint16(1), uint16(2), uint16(3)},
			mock:      isSetInputsOk[uint16],
		},
		{
			name:      "Valid uint8 input multiple data",
			expData:   "1,2,3",
			inputData: []any{uint8(1), uint8(2), uint8(3)},
			mock:      isSetInputsOk[uint8],
		},
		{
			name:      "Valid float64 input multiple data",
			expData:   "1,2,3",
			inputData: []any{float64(1), float64(2), float64(3)},
			mock:      isSetInputsOk[float64],
		},
		{
			name:      "Valid custom string data type",
			expData:   "1,2,3",
			inputData: []any{customString("1"), customString("2"), customString("3")},
			mock:      isSetInputsOk[customString],
		},
		{
			name:      "Valid custom int data type",
			expData:   "1,2,3",
			inputData: []any{customInt(1), customInt(2), customInt(3)},
			mock:      isSetInputsOk[customInt],
		},
		{
			name:      "Valid custom int64 data type",
			expData:   "1,2,3",
			inputData: []any{customInt64(1), customInt64(2), customInt64(3)},
			mock:      isSetInputsOk[customInt64],
		},
		{
			name:      "Valid custom uint64 data type",
			expData:   "1,2,3",
			inputData: []any{customUint64(1), customUint64(2), customUint64(3)},
			mock:      isSetInputsOk[customUint64],
		},
		{
			name:      "Valid custom uint32 data type",
			expData:   "1,2,3",
			inputData: []any{customUint32(1), customUint32(2), customUint32(3)},
			mock:      isSetInputsOk[customUint32],
		},
		{
			name:      "Valid custom float64 data type",
			expData:   "1,2,3",
			inputData: []any{customFloat64(1), customFloat64(2), customFloat64(3)},
			mock:      isSetInputsOk[customFloat64],
		},
		{
			name:      "Valid time duration data type",
			expData:   "1s",
			inputData: []any{time.Second},
			mock:      isSetInputsOk[time.Duration],
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.True(t, tc.mock(t, tc.expData, tc.inputData...))
		})
	}
}
