package meta

import (
	"reflect"
	"unsafe"
)

// IterFields - iterate through struct fields
func IterFields(val any, tagName string, f func(field any, tag string, offset uintptr)) {
	v := reflect.Indirect(reflect.ValueOf(val))
	t := v.Type()

	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)

		if fieldValue.CanInterface() && field.Type.Kind() == reflect.Struct {
			IterFields(fieldValue.Interface(), tagName, func(val any, tag string, offset uintptr) {
				f(val, tag, offset+field.Offset)
			})
		}
		if fieldValue.CanInterface() {
			f(fieldValue.Interface(), field.Tag.Get(tagName), field.Offset)
		}
	}
}

// IterFieldsTags - iterate through struct fields and list of tags
func IterFieldsTags(val any, tagNames []string, f func(field any, tag map[string]string, offset uintptr)) {
	v := reflect.Indirect(reflect.ValueOf(val))
	t := v.Type()

	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)

		if fieldValue.CanInterface() && field.Type.Kind() == reflect.Struct {
			IterFieldsTags(fieldValue.Interface(), tagNames, func(val any, tag map[string]string, offset uintptr) {
				f(val, tag, offset+field.Offset)
			})
		}
		tagsMap := make(map[string]string, len(tagNames))
		for _, tag := range tagNames {
			tagsMap[tag] = field.Tag.Get(tag)
		}

		if fieldValue.CanInterface() {
			f(fieldValue.Interface(), tagsMap, field.Offset)
		}
	}
}

// GetFieldTag - return object field tag
func GetFieldTag[T any](obj *T, objFieldPtr any, tagName string) string {
	tags := make(map[uintptr]string)

	IterFields(*obj, tagName, func(field any, tag string, offset uintptr) {
		if tag != "" {
			tags[offset] = tag
		}
	})

	return tags[reflect.ValueOf(objFieldPtr).Pointer()-(uintptr)(unsafe.Pointer(obj))]
}

// ListFieldTags - return list of tags of object field
func ListFieldTags[T any](obj *T, objFieldPtr any, tagNames ...string) (ret map[string]string) {
	ret = make(map[string]string)
	for _, tagName := range tagNames {
		ret[tagName] = GetFieldTag[T](obj, objFieldPtr, tagName)
	}
	return
}
