package apdu_test

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/smartcard/apdu"
)

const pin = "123456-test-pin"

func TestSecretCopiesAndUses(t *testing.T) {
	src := []byte(pin)
	s := apdu.NewSecret(src)
	clear(src)
	if s.Len() != len(pin) {
		t.Fatalf("len %d", s.Len())
	}
	called := 0
	s.Use(func(b []byte) {
		called++
		if string(b) != pin {
			t.Errorf("the secret changed with its source: %q", b)
		}
	})
	if called != 1 {
		t.Fatalf("Use called f %d times", called)
	}
}

func TestSecretWipe(t *testing.T) {
	s := apdu.NewSecret([]byte(pin))
	var kept []byte
	s.Use(func(b []byte) { kept = b })
	copyOfS := s
	s.Wipe()
	s.Wipe() // twice
	copyOfS.Wipe()
	if !bytes.Equal(kept, make([]byte, len(pin))) {
		t.Fatalf("the bytes are not overwritten: %x", kept)
	}
	if s.Len() != 0 || copyOfS.Len() != 0 {
		t.Fatal("a wiped secret holds bytes")
	}
	s.Use(func([]byte) { t.Fatal("Use called f on a wiped secret") })

	var zero apdu.Secret
	zero.Wipe()
	zero.Use(func([]byte) { t.Fatal("Use called f on a zero secret") })
	if zero.Len() != 0 {
		t.Fatal("zero secret has a length")
	}
}

func TestSecretPrintsNothing(t *testing.T) {
	s := apdu.NewSecret([]byte(pin))
	type wrapper struct {
		Name string
		PIN  apdu.Secret
		Ptr  *apdu.Secret
	}
	w := wrapper{"x", s, &s}
	var outs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T", "%10.3v", "%-20s"} {
		outs = append(outs, fmt.Sprintf(verb, s), fmt.Sprintf(verb, &s), fmt.Sprintf(verb, w), fmt.Sprintf(verb, []apdu.Secret{s}),
			fmt.Sprintf(verb, map[string]apdu.Secret{"k": s}))
	}
	outs = append(outs, fmt.Sprint(s), fmt.Sprintln(s, &s), s.String(), s.GoString(), fmt.Errorf("wrapped: %v", s).Error())
	text, err := s.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	outs = append(outs, string(text))
	j, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	outs = append(outs, string(j))
	var _ encoding.TextMarshaler = s
	var buf strings.Builder
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", "pin", s, "w", w)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("m", "pin", s, "w", w)
	outs = append(outs, buf.String())
	for _, o := range outs {
		if strings.Contains(o, "123456") || strings.Contains(o, "test-pin") || strings.Contains(strings.ToLower(o), "3132") {
			t.Errorf("a byte of the secret is shown: %q", o)
		}
	}
	if s.String() != "[secret]" || s.GoString() != "[secret]" || string(text) != "[secret]" || fmt.Sprintf("%v", s) != "[secret]" {
		t.Errorf("not the fixed word: %q", s.String())
	}
	if !strings.Contains(string(j), `"PIN":"[secret]"`) {
		t.Errorf("json: %s", j)
	}
}

// shownPIN reports whether out holds the bytes of the PIN in any of the forms that fmt, an encoder or a
// dump uses.
func shownPIN(out string, pin []byte) bool {
	var dec, goHex []string
	for _, b := range pin {
		dec = append(dec, fmt.Sprint(b))
		goHex = append(goHex, fmt.Sprintf("0x%02x", b))
	}
	forms := []string{
		string(pin), fmt.Sprintf("%x", pin), fmt.Sprintf("%X", pin), fmt.Sprintf("% x", pin), fmt.Sprintf("% X", pin),
		strings.Join(dec, " "), strings.Join(dec, ","), strings.Join(goHex, ", "), base64.StdEncoding.EncodeToString(pin),
	}
	for _, f := range forms {
		if strings.Contains(out, f) {
			return true
		}
	}
	return false
}

type secretExported struct {
	Name string
	S    apdu.Secret
	P    *apdu.Secret
}

type secretUnexported struct {
	name string
	s    apdu.Secret
	p    *apdu.Secret
}

type cmdUnexported struct{ c apdu.Command }

// sweep prints every value with every verb and a set of flags, and through the other ways that a
// program prints, and fails when a byte of the PIN is shown.
func sweep(t *testing.T, pin []byte, values map[string]any) {
	t.Helper()
	tried := 0
	for name, v := range values {
		for _, verb := range "vVsqxXdbcoOtTUeEfFgGp" {
			for _, flags := range []string{"", "+", "#", "-", " ", "0", "+#", "10", ".3", "-20.4", "08"} {
				format := "%" + flags + string(verb)
				out := fmt.Sprintf(format, v)
				tried++
				if shownPIN(out, pin) {
					t.Errorf("%s with %s shows the PIN: %q", name, format, out)
				}
			}
		}
		for _, out := range []string{fmt.Sprint(v), fmt.Sprintln(v), fmt.Sprint(v, v), fmt.Errorf("e: %v", v).Error(), fmt.Errorf("e: %w", fmt.Errorf("%+v", v)).Error()} {
			if shownPIN(out, pin) {
				t.Errorf("%s printed plainly shows the PIN: %q", name, out)
			}
		}
		for _, enc := range []struct {
			name string
			f    func(any) ([]byte, error)
		}{
			{"json", json.Marshal},
			{"json indent", func(v any) ([]byte, error) { return json.MarshalIndent(v, "", " ") }},
			{"xml", xml.Marshal},
			{"gob", func(v any) ([]byte, error) {
				var b bytes.Buffer
				err := gob.NewEncoder(&b).Encode(v)
				return b.Bytes(), err
			}},
		} {
			out, _ := enc.f(v) // an encoder may refuse; what it wrote must hold no byte
			if shownPIN(string(out), pin) {
				t.Errorf("%s through %s shows the PIN: %q", name, enc.name, out)
			}
		}
		var buf bytes.Buffer
		slog.New(slog.NewTextHandler(&buf, nil)).Info("m", "v", v)
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", "v", v)
		if shownPIN(buf.String(), pin) {
			t.Errorf("%s logged shows the PIN: %q", name, buf.String())
		}
	}
	if tried < 1000 {
		t.Fatalf("only %d formats were tried", tried)
	}
}

// A Secret keeps its bytes where printing by reflection cannot follow: by value, by pointer, in an exported
// and in an unexported field, in a slice, a map, an array and an interface, with every verb.
func TestSecretNoVerbShowsTheBytes(t *testing.T) {
	pin := []byte("Xk9#mQ2$")
	s := apdu.NewSecret(pin)
	var iface any = s
	sweep(t, pin, map[string]any{
		"value": s, "pointer": &s, "interface": iface, "zero": apdu.Secret{},
		"exported field": secretExported{"n", s, &s}, "exported field, pointer": &secretExported{"n", s, &s},
		"unexported field": secretUnexported{"n", s, &s}, "unexported field, pointer": &secretUnexported{"n", s, &s},
		"anonymous unexported": struct{ s apdu.Secret }{s}, "slice": []apdu.Secret{s}, "array": [1]apdu.Secret{s},
		"map value": map[string]apdu.Secret{"k": s}, "slice of structs": []secretUnexported{{"n", s, &s}},
		"interface slice": []any{s, &s}, "reflect.Value": reflect.ValueOf(s),
	})
	// Copies are the same secret; the type is comparable.
	c := s
	if c != s {
		t.Fatal("a copy is not equal to the secret")
	}
	s.Wipe()
	if c.Len() != 0 {
		t.Fatal("the wipe did not reach the copy")
	}
}

// A Command that carries its body as a Secret holds no PIN that a print or an encoder could reach: in any
// field, with any verb.
func TestCommandWithASecretBodyShowsNoPIN(t *testing.T) {
	pin := []byte("Xk9#mQ2$")
	c := apdu.Command{INS: 0x20, P2: 0x81, Le: 256}.WithSecretData(apdu.NewSecret(pin))
	two := apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(apdu.NewSecret(pin), apdu.NewSecret(pin))
	sweep(t, pin, map[string]any{
		"value": c, "pointer": &c, "pair": two, "unexported field": cmdUnexported{c}, "unexported field, pointer": &cmdUnexported{c},
		"slice of unexported": []cmdUnexported{{c}, {two}}, "anonymous": struct{ c apdu.Command }{c},
		"exported": struct{ C apdu.Command }{c}, "map value": map[string]apdu.Command{"k": c},
	})
	// The bytes are in the encoded command, and nowhere else.
	enc, err := c.Encode(false)
	if err != nil || !bytes.Equal(enc, append([]byte{0, 0x20, 0, 0x81, 8}, append(append([]byte{}, pin...), 0)...)) {
		t.Fatalf("%v %x", err, enc)
	}
	enc, err = two.Encode(true)
	if err != nil || !bytes.Equal(enc, append(append([]byte{0, 0x24, 0, 0x81, 0, 0, 16}, pin...), pin...)) {
		t.Fatalf("%v %x", err, enc)
	}
	if c.BodyLen() != 8 || two.BodyLen() != 16 || c.SecretParts() != 1 || two.SecretParts() != 2 || !c.HasSecret() || (apdu.Command{}).HasSecret() {
		t.Fatal("body accessors")
	}
}

func TestCommandBodyRules(t *testing.T) {
	pin := []byte("123456")
	both := apdu.Command{INS: 0x20}.WithSecretData(apdu.NewSecret(pin))
	both.Data = pin
	if out, err := both.Encode(false); !errors.Is(err, apdu.ErrBodyConflict) || out != nil {
		t.Fatalf("both: %v", err)
	}
	// WithSecretData replaces Data.
	c := apdu.Command{INS: 0x20, Data: pin}.WithSecretData(apdu.NewSecret(pin[:2]))
	if len(c.Data) != 0 || c.BodyLen() != 2 {
		t.Fatal("Data survived WithSecretData")
	}
	// A wiped secret is refused, not encoded as an empty body: that would be an empty VERIFY.
	w := apdu.NewSecret(pin)
	cw := apdu.Command{INS: 0x20}.WithSecretData(w)
	w.Wipe()
	if out, err := cw.Encode(false); !errors.Is(err, apdu.ErrSecretEmpty) || !errors.Is(err, apdu.ErrSecretChanged) || out != nil {
		t.Fatalf("wiped: %v %x", err, out)
	}
	// A pair with a wiped old PIN is refused, in either position: the card would split the new PIN by its
	// own length for the old one.
	for _, wipeFirst := range []bool{true, false} {
		old, nw := apdu.NewSecret(pin), apdu.NewSecret(pin)
		if wipeFirst {
			old.Wipe()
		} else {
			nw.Wipe()
		}
		if out, err := (apdu.Command{INS: 0x24}).WithSecretPair(old, nw).Encode(true); !errors.Is(err, apdu.ErrSecretEmpty) || out != nil {
			t.Fatalf("wiped pair: %v %x", err, out)
		}
	}
	if apdu.EncodedLen(0, 0, false) != 4 || apdu.EncodedLen(6, 0, false) != 11 || apdu.EncodedLen(6, 256, false) != 12 ||
		apdu.EncodedLen(0, 256, true) != 7 || apdu.EncodedLen(6, 0, true) != 13 || apdu.EncodedLen(6, 256, true) != 15 {
		t.Fatal("EncodedLen")
	}
	// Too long a secret for the form.
	big := apdu.Command{INS: 0xDA}.WithSecretData(apdu.NewSecret(make([]byte, 256)))
	if _, err := big.Encode(false); !errors.Is(err, apdu.ErrDataTooLong) {
		t.Fatalf("%v", err)
	}
	if _, err := big.Encode(true); err != nil {
		t.Fatalf("%v", err)
	}
	// The same Secret twice is no deadlock.
	s := apdu.NewSecret(pin)
	if out, err := (apdu.Command{INS: 0x24}).WithSecretPair(s, s).Encode(false); err != nil || len(out) != 4+1+12 {
		t.Fatalf("%v", err)
	}
}
