package strictjson

import (
	"bytes"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"

	"ritueel.id/ritueel/internal/jsonset"
)

// Unmarshal reads data under the rules of the package comment and fills the value that v points
// to. v must be a non-nil pointer to a struct, a map, a Raw, an interface with no methods, or a
// pointer to one of the first three; a Go type outside the set that the package comment lists is
// refused before a byte of data is looked at. A member of the document must be spelt
// exactly as the field's JSON name; unless opts.AllowUnknown is set, a member that names no field
// is an error, at any depth. Members the caller needs are the caller's to check: a field whose
// member is missing is zero. The value is replaced as a whole, and on an error it is as it was.
func Unmarshal(data []byte, v any, opts Options) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.New("strictjson: Unmarshal needs a non-nil pointer")
	}
	t := rv.Type().Elem()
	f := &filler{
		checker:      jsonset.NewChecker(jsonset.Reading, rawType),
		data:         data,
		allowUnknown: opts.AllowUnknown,
		names:        map[reflect.Type]map[string]jsonset.Field{},
	}
	if err := f.checkRoot(t); err != nil {
		return err
	}
	root, err := parseDocument(data, limit(opts.MaxBytes), true)
	if err != nil {
		return err
	}
	fresh := reflect.New(t).Elem()
	if err := f.fill(fresh, root); err != nil {
		return err
	}
	rv.Elem().Set(fresh)
	return nil
}

// filler fills a value from the parsed document.
type filler struct {
	checker      *jsonset.Checker
	data         []byte
	allowUnknown bool
	path         jsonset.Path
	names        map[reflect.Type]map[string]jsonset.Field
}

// checkRoot refuses the type of the target when it is outside the set, or when no document can
// fill it: the top of a document is one object.
func (f *filler) checkRoot(t reflect.Type) error {
	if r := f.checker.Verdict(t); r != nil {
		return f.checker.Err(nil, r)
	}
	u := t
	if u.Kind() == reflect.Pointer {
		u = u.Elem()
	}
	switch {
	case u == rawType, u.Kind() == reflect.Struct, u.Kind() == reflect.Map, u.Kind() == reflect.Interface:
		return nil
	}
	return jsonset.Errorf(nil, "a value of type %s cannot be read: the top of a document is one JSON object, which fills a struct, a map, a Raw or an interface with no methods", t)
}

// kindName says what a kind of value is, for an error.
func kindName(k Kind) string {
	switch k {
	case Object:
		return "an object"
	case List:
		return "a list"
	case String:
		return "a string"
	case Integer:
		return "an integer"
	case Bool:
		return "true or false"
	default:
		return "something else"
	}
}

// mismatch is the error for a value of the document that is not of the kind the target needs.
func (f *filler) mismatch(want string, n *Value) error {
	return jsonset.Errorf(f.path, "expected %s, found %s", want, kindName(n.Kind))
}

// fill fills dst, a zero value of a type that passed the checker, from n.
func (f *filler) fill(dst reflect.Value, n *Value) error {
	t := dst.Type()
	if t == rawType {
		if n.Kind != Object {
			return f.mismatch("one JSON object, for a Raw", n)
		}
		dst.SetBytes(bytes.Clone(f.data[n.Start:n.End]))
		return nil
	}
	switch t.Kind() {
	case reflect.Bool:
		if n.Kind != Bool {
			return f.mismatch("true or false", n)
		}
		dst.SetBool(n.Bool)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if n.Kind != Integer {
			return f.mismatch("an integer", n)
		}
		if dst.OverflowInt(n.Int) {
			return jsonset.Errorf(f.path, "the integer %d does not fit the type %s", n.Int, t)
		}
		dst.SetInt(n.Int)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if n.Kind != Integer {
			return f.mismatch("an integer", n)
		}
		if n.Int < 0 || dst.OverflowUint(uint64(n.Int)) {
			return jsonset.Errorf(f.path, "the integer %d does not fit the type %s", n.Int, t)
		}
		dst.SetUint(uint64(n.Int))
	case reflect.String:
		if n.Kind != String {
			return f.mismatch("a string", n)
		}
		dst.SetString(n.Str)
	case reflect.Pointer:
		p := reflect.New(t.Elem())
		if err := f.fill(p.Elem(), n); err != nil {
			return err
		}
		dst.Set(p)
	case reflect.Interface:
		dst.Set(reflect.ValueOf(anyOf(n)))
	case reflect.Struct:
		return f.fillStruct(dst, n)
	case reflect.Map:
		return f.fillMap(dst, n)
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return f.fillBytes(dst, n)
		}
		if n.Kind != List {
			return f.mismatch("a list", n)
		}
		s := reflect.MakeSlice(t, len(n.Elems), len(n.Elems))
		if err := f.fillElems(s, n); err != nil {
			return err
		}
		dst.Set(s)
	case reflect.Array:
		if n.Kind != List {
			return f.mismatch("a list", n)
		}
		if len(n.Elems) != t.Len() {
			return jsonset.Errorf(f.path, "the list has %d elements, and the array of type %s holds exactly %d", len(n.Elems), t, t.Len())
		}
		return f.fillElems(dst, n)
	default:
		return jsonset.Errorf(f.path, "a value of type %s cannot be read: this kind of Go type is not part of ritueel's JSON", t)
	}
	return nil
}

// anyOf is the value of the document for a target of interface kind: a map[string]any for an
// object, a []any for a list, a string, a bool, and an int64 for a number.
func anyOf(n *Value) any {
	switch n.Kind {
	case Object:
		m := make(map[string]any, len(n.Members))
		for i := range n.Members {
			m[n.Members[i].Name] = anyOf(&n.Members[i].Value)
		}
		return m
	case List:
		l := make([]any, len(n.Elems))
		for i := range n.Elems {
			l[i] = anyOf(&n.Elems[i])
		}
		return l
	case String:
		return n.Str
	case Integer:
		return n.Int
	default:
		return n.Bool
	}
}

// fillElems fills the elements of a slice or an array from the list n.
func (f *filler) fillElems(dst reflect.Value, n *Value) error {
	for i := range n.Elems {
		f.path = append(f.path, jsonset.Element(i))
		if err := f.fill(dst.Index(i), &n.Elems[i]); err != nil {
			return err
		}
		f.path = f.path[:len(f.path)-1]
	}
	return nil
}

// fillBytes fills a slice of bytes from one string of standard Base64 with padding and zero
// padding bits: the string is decoded and encoded again, and must come back the same.
func (f *filler) fillBytes(dst reflect.Value, n *Value) error {
	if n.Kind != String {
		return f.mismatch("a string of standard Base64, for a slice of bytes", n)
	}
	decoded, err := base64.StdEncoding.DecodeString(n.Str)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != n.Str {
		return jsonset.Errorf(f.path, "not the one canonical spelling of Base64: standard alphabet, padding, zero padding bits, no line break")
	}
	s := reflect.MakeSlice(dst.Type(), len(decoded), len(decoded))
	copy(s.Bytes(), decoded)
	dst.Set(s)
	return nil
}

// fillMap fills a map whose key is of kind string.
func (f *filler) fillMap(dst reflect.Value, n *Value) error {
	if n.Kind != Object {
		return f.mismatch("an object", n)
	}
	t := dst.Type()
	m := reflect.MakeMapWithSize(t, len(n.Members))
	for i := range n.Members {
		member := &n.Members[i]
		f.path = append(f.path, jsonset.Member(member.Name))
		elem := reflect.New(t.Elem()).Elem()
		if err := f.fill(elem, &member.Value); err != nil {
			return err
		}
		key := reflect.New(t.Key()).Elem()
		key.SetString(member.Name)
		m.SetMapIndex(key, elem)
		f.path = f.path[:len(f.path)-1]
	}
	dst.Set(m)
	return nil
}

// fillStruct fills a struct: a member goes to the field whose JSON name is exactly its name.
func (f *filler) fillStruct(dst reflect.Value, n *Value) error {
	if n.Kind != Object {
		return f.mismatch("an object", n)
	}
	t := dst.Type()
	fields := f.names[t]
	if fields == nil {
		fields = map[string]jsonset.Field{}
		for _, field := range f.checker.Fields(t) {
			fields[field.Name] = field
		}
		f.names[t] = fields
	}
	for i := range n.Members {
		member := &n.Members[i]
		f.path = append(f.path, jsonset.Member(member.Name))
		field, ok := fields[member.Name]
		if !ok {
			// The standard decoder takes a name in any letter case for a field, so a file with
			// "Version" and "version" would be read by one that takes both; a name must be spelt as
			// the field's JSON name, and one that is spelt otherwise is not an unknown member.
			// The fields are walked in the order of their names, so that two fields that fold to
			// the name (k and K against the Kelvin sign) give the same error every time.
			for _, field := range f.checker.Fields(t) {
				if strings.EqualFold(field.Name, member.Name) {
					return jsonset.Errorf(f.path, "the member must be spelt %s", jsonset.Shown(field.Name))
				}
			}
			if !f.allowUnknown {
				return jsonset.Errorf(f.path, "unknown member")
			}
			f.path = f.path[:len(f.path)-1]
			continue
		}
		if err := f.fill(dst.Field(field.Index), &member.Value); err != nil {
			return err
		}
		f.path = f.path[:len(f.path)-1]
	}
	return nil
}
