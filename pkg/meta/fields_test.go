package meta

import (
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/suite"
)

type (
	TestStruct struct {
		ValScalarInt8            int8            `name:"int8" gr:"scalar"`
		ValScalarInt16           int16           `name:"int16" gr:"scalar"`
		ValScalarInt32           int32           `name:"int32" gr:"scalar"`
		ValScalarInt64           int64           `name:"int64" gr:"scalar"`
		ValScalarInt             int             `name:"int" gr:"scalar"`
		ValScalarUint8           uint8           `name:"uint8" gr:"scalar"`
		ValScalarUint16          uint16          `name:"uint16" gr:"scalar"`
		ValScalarUint32          uint32          `name:"uint32" gr:"scalar"`
		ValScalarUint64          uint64          `name:"uint64" gr:"scalar"`
		ValScalarUint            uint            `name:"uint" gr:"scalar"`
		ValScalarString          string          `name:"string" gr:"scalar"`
		ValScalarTime            time.Time       `name:"time" gr:"scalar-time"`
		ValScalarTimeDuration    time.Duration   `name:"duration" gr:"scalar-time"`
		ValScalarPtrInt8         *int8           `name:"*int8" gr:"scalar-ptr"`
		ValScalarPtrInt16        *int16          `name:"*int16" gr:"scalar-ptr"`
		ValScalarPtrInt32        *int32          `name:"*int32" gr:"scalar-ptr"`
		ValScalarPtrInt64        *int64          `name:"*int64" gr:"scalar-ptr"`
		ValScalarPtrInt          *int            `name:"*int" gr:"scalar-ptr"`
		ValScalarPtrUint8        *uint8          `name:"*uint8" gr:"scalar-ptr"`
		ValScalarPtrUint16       *uint16         `name:"*uint16" gr:"scalar-ptr"`
		ValScalarPtrUint32       *uint32         `name:"*uint32" gr:"scalar-ptr"`
		ValScalarPtrUint64       *uint64         `name:"*uint64" gr:"scalar-ptr"`
		ValScalarPtrUint         *uint           `name:"*uint" gr:"scalar-ptr"`
		ValScalarPtrString       *string         `name:"*string" gr:"scalar-ptr"`
		ValScalarPtrTime         *time.Time      `name:"*time" gr:"scalar-ptr-time"`
		ValScalarPtrTimeDuration *time.Duration  `name:"*duration" gr:"scalar-ptr-time"`
		ValVectorInt8            []int8          `name:"[]int8" gr:"vector"`
		ValVectorInt16           []int16         `name:"[]int16" gr:"vector"`
		ValVectorInt32           []int32         `name:"[]int32" gr:"vector"`
		ValVectorInt64           []int64         `name:"[]int64" gr:"vector"`
		ValVectorInt             []int           `name:"[]int" gr:"vector"`
		ValVectorUint8           []uint8         `name:"[]uint8" gr:"vector"`
		ValVectorUint16          []uint16        `name:"[]uint16" gr:"vector"`
		ValVectorUint32          []uint32        `name:"[]uint32" gr:"vector"`
		ValVectorUint64          []uint64        `name:"[]uint64" gr:"vector"`
		ValVectorUint            []uint          `name:"[]uint" gr:"vector"`
		ValVectorString          []string        `name:"[]string" gr:"vector"`
		ValVectorTime            []time.Time     `name:"[]time" gr:"vector-time"`
		ValVectorTimeDuration    []time.Duration `name:"[]duration" gr:"vector-time"`
	}
)

type flagsTestSuite struct {
	suite.Suite
}

func Test_Fields(t *testing.T) {
	suite.Run(t, new(flagsTestSuite))
}

func (sui *flagsTestSuite) Test_ListFieldTags() {
	obj := TestStruct{}
	tagNames := []string{"name", "gr"}
	testCases := []struct {
		name   string
		tag    []string
		fields map[uintptr]map[string]string
	}{
		{
			name: "test tag name and gr",
			tag:  tagNames,
			fields: map[uintptr]map[string]string{

				unsafe.Offsetof(obj.ValScalarInt8):            {tagNames[0]: "int8", tagNames[1]: "scalar"},
				unsafe.Offsetof(obj.ValScalarInt16):           {tagNames[0]: "int16", tagNames[1]: "scalar"},
				unsafe.Offsetof(obj.ValScalarInt32):           {tagNames[0]: "int32", tagNames[1]: "scalar"},
				unsafe.Offsetof(obj.ValScalarInt64):           {tagNames[0]: "int64", tagNames[1]: "scalar"},
				unsafe.Offsetof(obj.ValScalarInt):             {tagNames[0]: "int", tagNames[1]: "scalar"},
				unsafe.Offsetof(obj.ValScalarUint8):           {tagNames[0]: "uint8", tagNames[1]: "scalar"},
				unsafe.Offsetof(obj.ValScalarUint16):          {tagNames[0]: "uint16", tagNames[1]: "scalar"},
				unsafe.Offsetof(obj.ValScalarUint32):          {tagNames[0]: "uint32", tagNames[1]: "scalar"},
				unsafe.Offsetof(obj.ValScalarUint64):          {tagNames[0]: "uint64", tagNames[1]: "scalar"},
				unsafe.Offsetof(obj.ValScalarUint):            {tagNames[0]: "uint", tagNames[1]: "scalar"},
				unsafe.Offsetof(obj.ValScalarString):          {tagNames[0]: "string", tagNames[1]: "scalar"},
				unsafe.Offsetof(obj.ValScalarTime):            {tagNames[0]: "time", tagNames[1]: "scalar-time"},
				unsafe.Offsetof(obj.ValScalarTimeDuration):    {tagNames[0]: "duration", tagNames[1]: "scalar-time"},
				unsafe.Offsetof(obj.ValScalarPtrInt8):         {tagNames[0]: "*int8", tagNames[1]: "scalar-ptr"},
				unsafe.Offsetof(obj.ValScalarPtrInt16):        {tagNames[0]: "*int16", tagNames[1]: "scalar-ptr"},
				unsafe.Offsetof(obj.ValScalarPtrInt32):        {tagNames[0]: "*int32", tagNames[1]: "scalar-ptr"},
				unsafe.Offsetof(obj.ValScalarPtrInt64):        {tagNames[0]: "*int64", tagNames[1]: "scalar-ptr"},
				unsafe.Offsetof(obj.ValScalarPtrInt):          {tagNames[0]: "*int", tagNames[1]: "scalar-ptr"},
				unsafe.Offsetof(obj.ValScalarPtrUint8):        {tagNames[0]: "*uint8", tagNames[1]: "scalar-ptr"},
				unsafe.Offsetof(obj.ValScalarPtrUint16):       {tagNames[0]: "*uint16", tagNames[1]: "scalar-ptr"},
				unsafe.Offsetof(obj.ValScalarPtrUint32):       {tagNames[0]: "*uint32", tagNames[1]: "scalar-ptr"},
				unsafe.Offsetof(obj.ValScalarPtrUint64):       {tagNames[0]: "*uint64", tagNames[1]: "scalar-ptr"},
				unsafe.Offsetof(obj.ValScalarPtrUint):         {tagNames[0]: "*uint", tagNames[1]: "scalar-ptr"},
				unsafe.Offsetof(obj.ValScalarPtrString):       {tagNames[0]: "*string", tagNames[1]: "scalar-ptr"},
				unsafe.Offsetof(obj.ValScalarPtrTime):         {tagNames[0]: "*time", tagNames[1]: "scalar-ptr-time"},
				unsafe.Offsetof(obj.ValScalarPtrTimeDuration): {tagNames[0]: "*duration", tagNames[1]: "scalar-ptr-time"},
				unsafe.Offsetof(obj.ValVectorInt8):            {tagNames[0]: "[]int8", tagNames[1]: "vector"},
				unsafe.Offsetof(obj.ValVectorInt16):           {tagNames[0]: "[]int16", tagNames[1]: "vector"},
				unsafe.Offsetof(obj.ValVectorInt32):           {tagNames[0]: "[]int32", tagNames[1]: "vector"},
				unsafe.Offsetof(obj.ValVectorInt64):           {tagNames[0]: "[]int64", tagNames[1]: "vector"},
				unsafe.Offsetof(obj.ValVectorInt):             {tagNames[0]: "[]int", tagNames[1]: "vector"},
				unsafe.Offsetof(obj.ValVectorUint8):           {tagNames[0]: "[]uint8", tagNames[1]: "vector"},
				unsafe.Offsetof(obj.ValVectorUint16):          {tagNames[0]: "[]uint16", tagNames[1]: "vector"},
				unsafe.Offsetof(obj.ValVectorUint32):          {tagNames[0]: "[]uint32", tagNames[1]: "vector"},
				unsafe.Offsetof(obj.ValVectorUint64):          {tagNames[0]: "[]uint64", tagNames[1]: "vector"},
				unsafe.Offsetof(obj.ValVectorUint):            {tagNames[0]: "[]uint", tagNames[1]: "vector"},
				unsafe.Offsetof(obj.ValVectorString):          {tagNames[0]: "[]string", tagNames[1]: "vector"},
				unsafe.Offsetof(obj.ValVectorTime):            {tagNames[0]: "[]time", tagNames[1]: "vector-time"},
				unsafe.Offsetof(obj.ValVectorTimeDuration):    {tagNames[0]: "[]duration", tagNames[1]: "vector-time"},
			},
		},
	}

	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarInt8)], ListFieldTags(&obj, &obj.ValScalarInt8, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarInt16)], ListFieldTags(&obj, &obj.ValScalarInt16, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarInt32)], ListFieldTags(&obj, &obj.ValScalarInt32, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarInt64)], ListFieldTags(&obj, &obj.ValScalarInt64, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarInt)], ListFieldTags(&obj, &obj.ValScalarInt, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarUint8)], ListFieldTags(&obj, &obj.ValScalarUint8, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarUint16)], ListFieldTags(&obj, &obj.ValScalarUint16, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarUint32)], ListFieldTags(&obj, &obj.ValScalarUint32, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarUint64)], ListFieldTags(&obj, &obj.ValScalarUint64, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarUint)], ListFieldTags(&obj, &obj.ValScalarUint, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarString)], ListFieldTags(&obj, &obj.ValScalarString, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarTime)], ListFieldTags(&obj, &obj.ValScalarTime, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarTimeDuration)], ListFieldTags(&obj, &obj.ValScalarTimeDuration, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrInt8)], ListFieldTags(&obj, &obj.ValScalarPtrInt8, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrInt16)], ListFieldTags(&obj, &obj.ValScalarPtrInt16, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrInt32)], ListFieldTags(&obj, &obj.ValScalarPtrInt32, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrInt64)], ListFieldTags(&obj, &obj.ValScalarPtrInt64, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrInt)], ListFieldTags(&obj, &obj.ValScalarPtrInt, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrUint8)], ListFieldTags(&obj, &obj.ValScalarPtrUint8, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrUint16)], ListFieldTags(&obj, &obj.ValScalarPtrUint16, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrUint32)], ListFieldTags(&obj, &obj.ValScalarPtrUint32, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrUint64)], ListFieldTags(&obj, &obj.ValScalarPtrUint64, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrUint)], ListFieldTags(&obj, &obj.ValScalarPtrUint, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrString)], ListFieldTags(&obj, &obj.ValScalarPtrString, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrTime)], ListFieldTags(&obj, &obj.ValScalarPtrTime, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrTimeDuration)], ListFieldTags(&obj, &obj.ValScalarPtrTimeDuration, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorInt8)], ListFieldTags(&obj, &obj.ValVectorInt8, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorInt16)], ListFieldTags(&obj, &obj.ValVectorInt16, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorInt32)], ListFieldTags(&obj, &obj.ValVectorInt32, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorInt64)], ListFieldTags(&obj, &obj.ValVectorInt64, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorInt)], ListFieldTags(&obj, &obj.ValVectorInt, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorUint8)], ListFieldTags(&obj, &obj.ValVectorUint8, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorUint16)], ListFieldTags(&obj, &obj.ValVectorUint16, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorUint32)], ListFieldTags(&obj, &obj.ValVectorUint32, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorUint64)], ListFieldTags(&obj, &obj.ValVectorUint64, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorUint)], ListFieldTags(&obj, &obj.ValVectorUint, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorString)], ListFieldTags(&obj, &obj.ValVectorString, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorTime)], ListFieldTags(&obj, &obj.ValVectorTime, tc.tag...))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorTimeDuration)], ListFieldTags(&obj, &obj.ValVectorTimeDuration, tc.tag...))

		})
	}
}

func (sui *flagsTestSuite) Test_GetFieldTagFunc() {
	obj := TestStruct{}
	tagNames := []string{"name", "gr"}
	testCases := []struct {
		name   string
		tag    string
		fields map[uintptr]string
	}{
		{
			name: "test tag name",
			tag:  tagNames[0],
			fields: map[uintptr]string{
				unsafe.Offsetof(obj.ValScalarInt8):            "int8",
				unsafe.Offsetof(obj.ValScalarInt16):           "int16",
				unsafe.Offsetof(obj.ValScalarInt32):           "int32",
				unsafe.Offsetof(obj.ValScalarInt64):           "int64",
				unsafe.Offsetof(obj.ValScalarInt):             "int",
				unsafe.Offsetof(obj.ValScalarUint8):           "uint8",
				unsafe.Offsetof(obj.ValScalarUint16):          "uint16",
				unsafe.Offsetof(obj.ValScalarUint32):          "uint32",
				unsafe.Offsetof(obj.ValScalarUint64):          "uint64",
				unsafe.Offsetof(obj.ValScalarUint):            "uint",
				unsafe.Offsetof(obj.ValScalarString):          "string",
				unsafe.Offsetof(obj.ValScalarTime):            "time",
				unsafe.Offsetof(obj.ValScalarTimeDuration):    "duration",
				unsafe.Offsetof(obj.ValScalarPtrInt8):         "*int8",
				unsafe.Offsetof(obj.ValScalarPtrInt16):        "*int16",
				unsafe.Offsetof(obj.ValScalarPtrInt32):        "*int32",
				unsafe.Offsetof(obj.ValScalarPtrInt64):        "*int64",
				unsafe.Offsetof(obj.ValScalarPtrInt):          "*int",
				unsafe.Offsetof(obj.ValScalarPtrUint8):        "*uint8",
				unsafe.Offsetof(obj.ValScalarPtrUint16):       "*uint16",
				unsafe.Offsetof(obj.ValScalarPtrUint32):       "*uint32",
				unsafe.Offsetof(obj.ValScalarPtrUint64):       "*uint64",
				unsafe.Offsetof(obj.ValScalarPtrUint):         "*uint",
				unsafe.Offsetof(obj.ValScalarPtrString):       "*string",
				unsafe.Offsetof(obj.ValScalarPtrTime):         "*time",
				unsafe.Offsetof(obj.ValScalarPtrTimeDuration): "*duration",
				unsafe.Offsetof(obj.ValVectorInt8):            "[]int8",
				unsafe.Offsetof(obj.ValVectorInt16):           "[]int16",
				unsafe.Offsetof(obj.ValVectorInt32):           "[]int32",
				unsafe.Offsetof(obj.ValVectorInt64):           "[]int64",
				unsafe.Offsetof(obj.ValVectorInt):             "[]int",
				unsafe.Offsetof(obj.ValVectorUint8):           "[]uint8",
				unsafe.Offsetof(obj.ValVectorUint16):          "[]uint16",
				unsafe.Offsetof(obj.ValVectorUint32):          "[]uint32",
				unsafe.Offsetof(obj.ValVectorUint64):          "[]uint64",
				unsafe.Offsetof(obj.ValVectorUint):            "[]uint",
				unsafe.Offsetof(obj.ValVectorString):          "[]string",
				unsafe.Offsetof(obj.ValVectorTime):            "[]time",
				unsafe.Offsetof(obj.ValVectorTimeDuration):    "[]duration",
			},
		},
		{
			name: "test tag gr",
			tag:  tagNames[1],
			fields: map[uintptr]string{
				unsafe.Offsetof(obj.ValScalarInt8):            "scalar",
				unsafe.Offsetof(obj.ValScalarInt16):           "scalar",
				unsafe.Offsetof(obj.ValScalarInt32):           "scalar",
				unsafe.Offsetof(obj.ValScalarInt64):           "scalar",
				unsafe.Offsetof(obj.ValScalarInt):             "scalar",
				unsafe.Offsetof(obj.ValScalarUint8):           "scalar",
				unsafe.Offsetof(obj.ValScalarUint16):          "scalar",
				unsafe.Offsetof(obj.ValScalarUint32):          "scalar",
				unsafe.Offsetof(obj.ValScalarUint64):          "scalar",
				unsafe.Offsetof(obj.ValScalarUint):            "scalar",
				unsafe.Offsetof(obj.ValScalarString):          "scalar",
				unsafe.Offsetof(obj.ValScalarTime):            "scalar-time",
				unsafe.Offsetof(obj.ValScalarTimeDuration):    "scalar-time",
				unsafe.Offsetof(obj.ValScalarPtrInt8):         "scalar-ptr",
				unsafe.Offsetof(obj.ValScalarPtrInt16):        "scalar-ptr",
				unsafe.Offsetof(obj.ValScalarPtrInt32):        "scalar-ptr",
				unsafe.Offsetof(obj.ValScalarPtrInt64):        "scalar-ptr",
				unsafe.Offsetof(obj.ValScalarPtrInt):          "scalar-ptr",
				unsafe.Offsetof(obj.ValScalarPtrUint8):        "scalar-ptr",
				unsafe.Offsetof(obj.ValScalarPtrUint16):       "scalar-ptr",
				unsafe.Offsetof(obj.ValScalarPtrUint32):       "scalar-ptr",
				unsafe.Offsetof(obj.ValScalarPtrUint64):       "scalar-ptr",
				unsafe.Offsetof(obj.ValScalarPtrUint):         "scalar-ptr",
				unsafe.Offsetof(obj.ValScalarPtrString):       "scalar-ptr",
				unsafe.Offsetof(obj.ValScalarPtrTime):         "scalar-ptr-time",
				unsafe.Offsetof(obj.ValScalarPtrTimeDuration): "scalar-ptr-time",
				unsafe.Offsetof(obj.ValVectorInt8):            "vector",
				unsafe.Offsetof(obj.ValVectorInt16):           "vector",
				unsafe.Offsetof(obj.ValVectorInt32):           "vector",
				unsafe.Offsetof(obj.ValVectorInt64):           "vector",
				unsafe.Offsetof(obj.ValVectorInt):             "vector",
				unsafe.Offsetof(obj.ValVectorUint8):           "vector",
				unsafe.Offsetof(obj.ValVectorUint16):          "vector",
				unsafe.Offsetof(obj.ValVectorUint32):          "vector",
				unsafe.Offsetof(obj.ValVectorUint64):          "vector",
				unsafe.Offsetof(obj.ValVectorUint):            "vector",
				unsafe.Offsetof(obj.ValVectorString):          "vector",
				unsafe.Offsetof(obj.ValVectorTime):            "vector-time",
				unsafe.Offsetof(obj.ValVectorTimeDuration):    "vector-time",
			},
		},
	}

	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarInt8)], GetFieldTag(&obj, &obj.ValScalarInt8, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarInt16)], GetFieldTag(&obj, &obj.ValScalarInt16, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarInt32)], GetFieldTag(&obj, &obj.ValScalarInt32, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarInt64)], GetFieldTag(&obj, &obj.ValScalarInt64, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarInt)], GetFieldTag(&obj, &obj.ValScalarInt, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarUint8)], GetFieldTag(&obj, &obj.ValScalarUint8, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarUint16)], GetFieldTag(&obj, &obj.ValScalarUint16, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarUint32)], GetFieldTag(&obj, &obj.ValScalarUint32, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarUint64)], GetFieldTag(&obj, &obj.ValScalarUint64, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarUint)], GetFieldTag(&obj, &obj.ValScalarUint, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarString)], GetFieldTag(&obj, &obj.ValScalarString, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarTime)], GetFieldTag(&obj, &obj.ValScalarTime, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarTimeDuration)], GetFieldTag(&obj, &obj.ValScalarTimeDuration, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrInt8)], GetFieldTag(&obj, &obj.ValScalarPtrInt8, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrInt16)], GetFieldTag(&obj, &obj.ValScalarPtrInt16, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrInt32)], GetFieldTag(&obj, &obj.ValScalarPtrInt32, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrInt64)], GetFieldTag(&obj, &obj.ValScalarPtrInt64, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrInt)], GetFieldTag(&obj, &obj.ValScalarPtrInt, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrUint8)], GetFieldTag(&obj, &obj.ValScalarPtrUint8, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrUint16)], GetFieldTag(&obj, &obj.ValScalarPtrUint16, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrUint32)], GetFieldTag(&obj, &obj.ValScalarPtrUint32, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrUint64)], GetFieldTag(&obj, &obj.ValScalarPtrUint64, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrUint)], GetFieldTag(&obj, &obj.ValScalarPtrUint, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrString)], GetFieldTag(&obj, &obj.ValScalarPtrString, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrTime)], GetFieldTag(&obj, &obj.ValScalarPtrTime, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValScalarPtrTimeDuration)], GetFieldTag(&obj, &obj.ValScalarPtrTimeDuration, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorInt8)], GetFieldTag(&obj, &obj.ValVectorInt8, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorInt16)], GetFieldTag(&obj, &obj.ValVectorInt16, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorInt32)], GetFieldTag(&obj, &obj.ValVectorInt32, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorInt64)], GetFieldTag(&obj, &obj.ValVectorInt64, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorInt)], GetFieldTag(&obj, &obj.ValVectorInt, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorUint8)], GetFieldTag(&obj, &obj.ValVectorUint8, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorUint16)], GetFieldTag(&obj, &obj.ValVectorUint16, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorUint32)], GetFieldTag(&obj, &obj.ValVectorUint32, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorUint64)], GetFieldTag(&obj, &obj.ValVectorUint64, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorUint)], GetFieldTag(&obj, &obj.ValVectorUint, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorString)], GetFieldTag(&obj, &obj.ValVectorString, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorTime)], GetFieldTag(&obj, &obj.ValVectorTime, tc.tag))
			sui.Require().Equal(tc.fields[unsafe.Offsetof(obj.ValVectorTimeDuration)], GetFieldTag(&obj, &obj.ValVectorTimeDuration, tc.tag))
		})
	}
}

func (sui *flagsTestSuite) Test_IterFieldsTags() {
	obj := TestStruct{}
	tagNames := []string{"name", "gr"}
	testCases := []struct {
		offset uintptr
		tag    map[string]string
	}{
		{offset: unsafe.Offsetof(obj.ValScalarInt8), tag: map[string]string{tagNames[0]: "int8", tagNames[1]: "scalar"}},
		{offset: unsafe.Offsetof(obj.ValScalarInt16), tag: map[string]string{tagNames[0]: "int16", tagNames[1]: "scalar"}},
		{offset: unsafe.Offsetof(obj.ValScalarInt32), tag: map[string]string{tagNames[0]: "int32", tagNames[1]: "scalar"}},
		{offset: unsafe.Offsetof(obj.ValScalarInt64), tag: map[string]string{tagNames[0]: "int64", tagNames[1]: "scalar"}},
		{offset: unsafe.Offsetof(obj.ValScalarInt), tag: map[string]string{tagNames[0]: "int", tagNames[1]: "scalar"}},
		{offset: unsafe.Offsetof(obj.ValScalarUint8), tag: map[string]string{tagNames[0]: "uint8", tagNames[1]: "scalar"}},
		{offset: unsafe.Offsetof(obj.ValScalarUint16), tag: map[string]string{tagNames[0]: "uint16", tagNames[1]: "scalar"}},
		{offset: unsafe.Offsetof(obj.ValScalarUint32), tag: map[string]string{tagNames[0]: "uint32", tagNames[1]: "scalar"}},
		{offset: unsafe.Offsetof(obj.ValScalarUint64), tag: map[string]string{tagNames[0]: "uint64", tagNames[1]: "scalar"}},
		{offset: unsafe.Offsetof(obj.ValScalarUint), tag: map[string]string{tagNames[0]: "uint", tagNames[1]: "scalar"}},
		{offset: unsafe.Offsetof(obj.ValScalarString), tag: map[string]string{tagNames[0]: "string", tagNames[1]: "scalar"}},
		{offset: unsafe.Offsetof(obj.ValScalarTime), tag: map[string]string{tagNames[0]: "time", tagNames[1]: "scalar-time"}},
		{offset: unsafe.Offsetof(obj.ValScalarTimeDuration), tag: map[string]string{tagNames[0]: "duration", tagNames[1]: "scalar-time"}},
		{offset: unsafe.Offsetof(obj.ValScalarPtrInt8), tag: map[string]string{tagNames[0]: "*int8", tagNames[1]: "scalar-ptr"}},
		{offset: unsafe.Offsetof(obj.ValScalarPtrInt16), tag: map[string]string{tagNames[0]: "*int16", tagNames[1]: "scalar-ptr"}},
		{offset: unsafe.Offsetof(obj.ValScalarPtrInt32), tag: map[string]string{tagNames[0]: "*int32", tagNames[1]: "scalar-ptr"}},
		{offset: unsafe.Offsetof(obj.ValScalarPtrInt64), tag: map[string]string{tagNames[0]: "*int64", tagNames[1]: "scalar-ptr"}},
		{offset: unsafe.Offsetof(obj.ValScalarPtrInt), tag: map[string]string{tagNames[0]: "*int", tagNames[1]: "scalar-ptr"}},
		{offset: unsafe.Offsetof(obj.ValScalarPtrUint8), tag: map[string]string{tagNames[0]: "*uint8", tagNames[1]: "scalar-ptr"}},
		{offset: unsafe.Offsetof(obj.ValScalarPtrUint16), tag: map[string]string{tagNames[0]: "*uint16", tagNames[1]: "scalar-ptr"}},
		{offset: unsafe.Offsetof(obj.ValScalarPtrUint32), tag: map[string]string{tagNames[0]: "*uint32", tagNames[1]: "scalar-ptr"}},
		{offset: unsafe.Offsetof(obj.ValScalarPtrUint64), tag: map[string]string{tagNames[0]: "*uint64", tagNames[1]: "scalar-ptr"}},
		{offset: unsafe.Offsetof(obj.ValScalarPtrUint), tag: map[string]string{tagNames[0]: "*uint", tagNames[1]: "scalar-ptr"}},
		{offset: unsafe.Offsetof(obj.ValScalarPtrString), tag: map[string]string{tagNames[0]: "*string", tagNames[1]: "scalar-ptr"}},
		{offset: unsafe.Offsetof(obj.ValScalarPtrTime), tag: map[string]string{tagNames[0]: "*time", tagNames[1]: "scalar-ptr-time"}},
		{offset: unsafe.Offsetof(obj.ValScalarPtrTimeDuration), tag: map[string]string{tagNames[0]: "*duration", tagNames[1]: "scalar-ptr-time"}},
		{offset: unsafe.Offsetof(obj.ValVectorInt8), tag: map[string]string{tagNames[0]: "[]int8", tagNames[1]: "vector"}},
		{offset: unsafe.Offsetof(obj.ValVectorInt16), tag: map[string]string{tagNames[0]: "[]int16", tagNames[1]: "vector"}},
		{offset: unsafe.Offsetof(obj.ValVectorInt32), tag: map[string]string{tagNames[0]: "[]int32", tagNames[1]: "vector"}},
		{offset: unsafe.Offsetof(obj.ValVectorInt64), tag: map[string]string{tagNames[0]: "[]int64", tagNames[1]: "vector"}},
		{offset: unsafe.Offsetof(obj.ValVectorInt), tag: map[string]string{tagNames[0]: "[]int", tagNames[1]: "vector"}},
		{offset: unsafe.Offsetof(obj.ValVectorUint8), tag: map[string]string{tagNames[0]: "[]uint8", tagNames[1]: "vector"}},
		{offset: unsafe.Offsetof(obj.ValVectorUint16), tag: map[string]string{tagNames[0]: "[]uint16", tagNames[1]: "vector"}},
		{offset: unsafe.Offsetof(obj.ValVectorUint32), tag: map[string]string{tagNames[0]: "[]uint32", tagNames[1]: "vector"}},
		{offset: unsafe.Offsetof(obj.ValVectorUint64), tag: map[string]string{tagNames[0]: "[]uint64", tagNames[1]: "vector"}},
		{offset: unsafe.Offsetof(obj.ValVectorUint), tag: map[string]string{tagNames[0]: "[]uint", tagNames[1]: "vector"}},
		{offset: unsafe.Offsetof(obj.ValVectorString), tag: map[string]string{tagNames[0]: "[]string", tagNames[1]: "vector"}},
		{offset: unsafe.Offsetof(obj.ValVectorTime), tag: map[string]string{tagNames[0]: "[]time", tagNames[1]: "vector-time"}},
		{offset: unsafe.Offsetof(obj.ValVectorTimeDuration), tag: map[string]string{tagNames[0]: "[]duration", tagNames[1]: "vector-time"}},
	}

	sui.Run("iterate from object", func() {
		i := 0
		IterFieldsTags(obj, tagNames, func(field any, tag map[string]string, offset uintptr) {
			sui.Require().Equal(testCases[i].offset, offset)
			sui.Require().Equal(testCases[i].tag, tag)
			i++
		})
	})
	sui.Run("iterate from pointer of object", func() {
		i := 0
		IterFieldsTags(&obj, tagNames, func(field any, tag map[string]string, offset uintptr) {
			sui.Require().Equal(testCases[i].offset, offset)
			sui.Require().Equal(testCases[i].tag, tag)
			i++
		})
	})
	sui.Run("iterate from literal", func() {
		i := 0
		IterFieldsTags(TestStruct{}, tagNames, func(field any, tag map[string]string, offset uintptr) {
			sui.Require().Equal(testCases[i].offset, offset)
			sui.Require().Equal(testCases[i].tag, tag)
			i++
		})
	})
}
