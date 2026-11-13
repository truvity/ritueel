package strictjson

import (
	"bytes"
	"reflect"
)

// Raw is a JSON document that is read or written as it is: a signed or stored sub-document that
// sits inside another one. Unmarshal fills a Raw with the bytes of the member exactly as they
// are in the input, from its opening brace to its closing brace, so that a signature over them
// can be checked. A Raw holds one JSON object, as the whole of a document does; a member that is
// a list, a string, a number or a boolean cannot fill one. A Raw is read through the same reader
// as the document around it, so every rule holds inside it too, the range of the integers
// (MinSafeInt to MaxSafeInt) included. Package canonjson writes a Raw in its canonical form and
// names the type canonjson.Raw too: the two names are one type. A pointer to
// a Raw is a pointer like any other: Unmarshal makes it for a member that is present, Marshal
// writes what it points to, and a nil one is left out under omitempty.
type Raw []byte

// rawType is the one Go type that may have its own UnmarshalJSON and MarshalJSON methods.
var rawType = reflect.TypeFor[Raw]()

// MarshalJSON returns r unchanged, so that the standard encoder writes a Raw as it writes a
// json.RawMessage, after the check that Unmarshal and canonjson.Marshal make: r is one JSON
// object under the rules of Check. An empty Raw is an error, not null. Neither this package nor
// canonjson calls it.
func (r Raw) MarshalJSON() ([]byte, error) {
	if err := Check(r, DefaultMaxBytes); err != nil {
		return nil, err
	}
	return r, nil
}

// UnmarshalJSON stores a copy of the bytes of the document, after the check that Unmarshal makes:
// the data is one JSON object under the rules of Check. Neither this package nor canonjson calls
// it.
func (r *Raw) UnmarshalJSON(data []byte) error {
	if err := Check(data, DefaultMaxBytes); err != nil {
		return err
	}
	*r = bytes.Clone(data)
	return nil
}
