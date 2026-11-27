package apdu_test

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
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
