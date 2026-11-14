package pki

import "reflect"

// isNil tells whether v is nil, or an interface that holds a nil pointer, map, slice, function or
// channel. A nil pointer in an interface is not equal to nil, and calling a method on it may panic
// or work on nothing; an exported function of this package treats it as no value at all.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	switch r := reflect.ValueOf(v); r.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return r.IsNil()
	}
	return false
}
