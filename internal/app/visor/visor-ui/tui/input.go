package tui

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unsafe"

	vf "github.com/wildberries-tech/pkt-tracer/internal/app/visor/flags"

	"github.com/gdamore/tcell/v2"
	"github.com/pkg/errors"
	"github.com/rivo/tview"
)

type (
	AvailableInputTypes interface {
		~int | ~uint |
			~int64 | ~uint64 |
			~int32 | ~uint32 |
			~int16 | ~uint16 |
			~int8 | ~uint8 |
			~float32 | ~float64 |
			~string
	}
	InputOPtions struct {
		Name        string
		Description string
		Title       string
		Label       string
		PlaceHolder string
		FieldWidth  int
		Border      bool
		Action      ActionHandler
	}
	InputFace interface {
		Primitive
		SetText(text string) *tview.InputField
		GetText() string
	}
	Input[T AvailableInputTypes] struct {
		*tview.InputField
		PrimitiveName
	}
)

var _ InputFace = (*Input[string])(nil)

// NewInputByType - create new input object using auto instantiation
func NewInputByType[T AvailableInputTypes](opt InputOPtions, Type ...T) *Input[T] {
	return NewInput[T](opt)
}

// NewInput - create new input object of type
func NewInput[T AvailableInputTypes](opt InputOPtions) *Input[T] {
	i := &Input[T]{tview.NewInputField(), PrimitiveName(opt.Name)}
	i.SetText(opt.Description).
		SetFieldTextColor(tcell.ColorWhite).
		SetLabel(fmt.Sprintf(" %-10s ", opt.Label)).
		SetPlaceholder(fmt.Sprintf("start typing... (e.g.: %s)", opt.PlaceHolder)).
		SetPlaceholderTextColor(tcell.ColorWhite).
		SetFieldWidth(opt.FieldWidth).
		SetChangedFunc(func(text string) {
			i.SetFieldBackgroundColor(tcell.ColorGreen)
		})

	if opt.Border {
		i.SetBorder(true).SetTitle(opt.Title)
	}
	if opt.Action != nil {
		i.SetInputCapture(opt.Action)
	}

	return i
}

// GetInputValues - get values from inputs separated by character
func (i *Input[T]) GetInputValues(sep string) (ret []T, err error) {
	var inputVal T
	inputType := reflect.TypeOf(inputVal).Kind()
	strVals := strings.Split(i.GetText(), sep)
	if len(strVals) == 1 && strVals[0] == "" {
		return ret, err
	}
	for i := range strVals {
		switch inputType {
		case reflect.String:
			err = vf.ValidateStringValue(strVals[i])
			inputVal = *(*T)(unsafe.Pointer(&strVals[i]))
		case reflect.Float64:
			var v float64
			v, err = strconv.ParseFloat(strVals[i], 64)
			inputVal = *(*T)(unsafe.Pointer(&v))
		default:
			if v, ok := reflect.ValueOf(inputVal).Interface().(time.Duration); ok {
				v, err = time.ParseDuration(strVals[i])
				inputVal = *(*T)(unsafe.Pointer(&v))
			} else {
				var v int
				v, err = strconv.Atoi(strVals[i])
				inputVal = *(*T)(unsafe.Pointer(&v))
			}
		}
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to parse input value='%s'. Type of value must be: '%T'", strVals[i], inputVal)
		}
		ret = append(ret, inputVal)
	}
	return ret, err
}

func (i *Input[T]) SetInputValues(values ...T) {
	var v []string
	for i := range values {
		t := reflect.TypeOf(values[i])
		switch t.Kind() {
		case reflect.String:
			v = append(v, *(*string)(unsafe.Pointer(&values[i])))
		case reflect.Float64:
			v = append(v, strconv.FormatFloat(*(*float64)(unsafe.Pointer(&values[i])), 'f', -1, 64))
		case reflect.Uint8:
			v = append(v, strconv.FormatUint(uint64(*(*uint8)(unsafe.Pointer(&values[i]))), 10))
		case reflect.Uint16:
			v = append(v, strconv.FormatUint(uint64(*(*uint16)(unsafe.Pointer(&values[i]))), 10))
		case reflect.Uint32:
			v = append(v, strconv.FormatUint(uint64(*(*uint32)(unsafe.Pointer(&values[i]))), 10))
		case reflect.Uint64:
			v = append(v, strconv.FormatUint(*(*uint64)(unsafe.Pointer(&values[i])), 10))
		case reflect.Uint:
			v = append(v, strconv.FormatUint(uint64(*(*uint)(unsafe.Pointer(&values[i]))), 10))
		case reflect.Int8:
			v = append(v, strconv.Itoa(int(*(*int8)(unsafe.Pointer(&values[i])))))
		case reflect.Int16:
			v = append(v, strconv.Itoa(int(*(*int16)(unsafe.Pointer(&values[i])))))
		case reflect.Int32:
			v = append(v, strconv.Itoa(int(*(*int32)(unsafe.Pointer(&values[i])))))
		case reflect.Int64:
			if t, ok := reflect.ValueOf(values[i]).Interface().(time.Duration); ok {
				v = append(v, t.String())
			} else {
				v = append(v, strconv.FormatInt(*(*int64)(unsafe.Pointer(&values[i])), 10))
			}
		case reflect.Int:
			v = append(v, strconv.Itoa(*(*int)(unsafe.Pointer(&values[i]))))
		}
	}

	i.SetText(strings.Join(v, ","))
}

// Helpers...

// GetInputValues - get values from inputs separated by character
func GetInputValues[T AvailableInputTypes](input InputFace, sep string) ([]T, error) {
	in, ok := input.((*Input[T]))
	if !ok {
		var val T
		wantType := reflect.TypeOf(val).Name()
		actualType := reflect.TypeOf(input).Name()
		return nil, errors.Errorf("mismatch input types! want: '%s', actual: '%s'", wantType, actualType)
	}
	return in.GetInputValues(sep)
}

// GetInputValuesByType - get values from inputs using auto instantiation
func GetInputValuesByType[T AvailableInputTypes](input InputFace, sep string, Type ...T) ([]T, error) {
	return GetInputValues[T](input, sep)
}

// SetInputValues - set values into input field
func SetInputValues[T AvailableInputTypes](input InputFace, values ...T) error {
	in, ok := input.((*Input[T]))
	if !ok {
		var val T
		wantType := reflect.TypeOf(val).Name()
		actualType := reflect.TypeOf(input).Name()
		return errors.Errorf("mismatch input types! want: '%s', actual: '%s'", wantType, actualType)
	}
	in.SetInputValues(values...)
	return nil
}
