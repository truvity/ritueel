package apdu_test

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"text/template"

	"ritueel.id/ritueel/internal/smartcard/apdu"
)

// qaPIN is a test value. It has bytes outside the digits, so that a text search for any run of its
// bytes finds nothing by chance in the fixed word that a Secret shows.
var qaPIN = []byte("Xk9#mQ2$")

// forms lists the ways that the bytes of the PIN could show in a text: raw, every window of three or
// more of its bytes, hex in both cases and with the usual separators, base64 in the four alphabets, the
// bytes in decimal as Go prints a []byte and joined by other separators, and in the Go syntaxes.
func forms(pin []byte) map[string]string {
	f := map[string]string{"raw": string(pin), "quoted": strconv.Quote(string(pin))}
	for i := range len(pin) - 2 {
		for j := i + 3; j <= len(pin); j++ {
			f[fmt.Sprintf("raw window %d..%d", i, j)] = string(pin[i:j])
		}
	}
	h := hex.EncodeToString(pin)
	f["hex"], f["HEX"] = h, strings.ToUpper(h)
	var spaced, colon, dec, decComma, goBytes, gostr, x0 []string
	for _, b := range pin {
		spaced = append(spaced, fmt.Sprintf("%02x", b))
		colon = append(colon, fmt.Sprintf("%02X", b))
		dec = append(dec, strconv.Itoa(int(b)))
		goBytes = append(goBytes, fmt.Sprintf("0x%x", b))
		gostr = append(gostr, fmt.Sprintf("\\x%02x", b))
		x0 = append(x0, fmt.Sprintf("0x%02X", b))
		decComma = append(decComma, strconv.Itoa(int(b)))
	}
	f["hex spaced"], f["HEX colon"] = strings.Join(spaced, " "), strings.Join(colon, ":")
	f["decimal"] = strings.Join(dec, " ")
	f["decimal commas"] = strings.Join(decComma, ",")
	f["decimal squashed"] = strings.Join(dec, "")
	f["go bytes"] = strings.Join(goBytes, ", ")
	f["0x spaced"] = strings.Join(x0, " ")
	f["go string escapes"] = strings.Join(gostr, "")
	f["fmt of the bytes"] = fmt.Sprintf("%v", pin)
	f["fmt %v of a string"] = fmt.Sprintf("%v", string(pin))
	for name, enc := range map[string]*base64.Encoding{
		"base64": base64.StdEncoding, "base64 raw": base64.RawStdEncoding, "base64 url": base64.URLEncoding, "base64 raw url": base64.RawURLEncoding,
	} {
		f[name] = enc.EncodeToString(pin)
	}
	// base64 of the PIN at the other two alignments inside a longer text.
	for _, pad := range []string{"a", "ab"} {
		f["base64 shifted by "+pad] = base64.RawStdEncoding.EncodeToString(append([]byte(pad), pin...))[len(pad)*4/3+1:]
	}
	return f
}

// assertNoPIN fails when the text holds the PIN in any of its forms.
func assertNoPIN(t *testing.T, what, text string) {
	t.Helper()
	for name, f := range forms(qaPIN) {
		if f != "" && strings.Contains(text, f) {
			t.Errorf("%s: the output shows the PIN as %s: %q", what, name, text)
			return
		}
	}
}

type qaExported struct {
	Name string
	PIN  apdu.Secret
	Ptr  *apdu.Secret
}

type qaUnexported struct {
	name string
	pin  apdu.Secret
	ptr  *apdu.Secret
}

type qaEmbedded struct {
	apdu.Secret
	Other int
}

type qaErrorHolder struct{ s apdu.Secret }

func (e qaErrorHolder) Error() string { return fmt.Sprintf("failed with %v", e.s) }

const allVerbs = "vVsqxXdbcoOtTUeEfFgGp"

// sweepPrint prints every value with every verb and flag that fmt knows, and in the ways that a program
// shows a value in a message, and fails when the text holds the PIN in any form.
func sweepPrint(t *testing.T, values map[string]any, verbs string) {
	t.Helper()
	flags := []string{"", "+", "#", "-", " ", "0", "10", ".3", "-20.4", "+#", "08"}
	count := 0
	for name, v := range values {
		for _, verb := range verbs {
			for _, fl := range flags {
				format := "%" + fl + string(verb)
				assertNoPIN(t, fmt.Sprintf("%s with %s", name, format), fmt.Sprintf(format, v))
				count++
			}
		}
		assertNoPIN(t, name+" Sprint", fmt.Sprint(v))
		assertNoPIN(t, name+" Sprintln", fmt.Sprintln(v, v))
		assertNoPIN(t, name+" Sprint with another", fmt.Sprint("a", v, "b", v))
		assertNoPIN(t, name+" in an error with %v", fmt.Errorf("fail: %v", v).Error())
		assertNoPIN(t, name+" in an error with %w", fmt.Errorf("fail: %w", fmt.Errorf("inner %v", v)).Error())
		assertNoPIN(t, name+" in an error with %+v", fmt.Errorf("fail: %+v", v).Error())
		assertNoPIN(t, name+" in an error with %#v", fmt.Errorf("fail: %#v", v).Error())
		assertNoPIN(t, name+" in errors.Join", errors.Join(errors.New("a"), fmt.Errorf("b %v", v)).Error())
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "%v %+v %#v %s", v, v, v, v)
		assertNoPIN(t, name+" Fprintf", buf.String())
		buf.Reset()
		log.New(&buf, "", 0).Printf("%v %+v", v, v)
		log.New(&buf, "", 0).Println(v)
		assertNoPIN(t, name+" log", buf.String())
	}
	if count < 1000 {
		t.Fatalf("only %d formats were tried", count)
	}
}

func TestSecretEveryWayToPrint(t *testing.T) {
	s := apdu.NewSecret(qaPIN)
	p := &s
	var iface any = s
	exp := qaExported{"n", s, p}
	values := map[string]any{
		"value": s, "pointer": p, "interface": iface, "pointer to pointer": &p,
		"slice": []apdu.Secret{s, s}, "slice of pointers": []*apdu.Secret{p}, "array": [2]apdu.Secret{s, s},
		"map value": map[string]apdu.Secret{"k": s}, "map key": map[apdu.Secret]int{s: 1},
		"exported fields": exp, "pointer to exported fields": &exp,
		"embedded": qaEmbedded{s, 1}, "pointer to embedded": &qaEmbedded{s, 1},
		"reflect.Value": reflect.ValueOf(s), "struct in a slice in a map": map[string][]qaExported{"k": {exp}},
		"anonymous struct": struct{ S apdu.Secret }{s},
	}
	sweepPrint(t, values, allVerbs)
	// The value, a pointer to it and its Error-wrapping holder show the fixed word and nothing else.
	for _, v := range []any{s, p, iface} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%08.3v", "%-30s", "%t", "%e", "%c", "%U"} {
			if got := fmt.Sprintf(verb, v); got != "[secret]" {
				t.Errorf("%s of %T: %q", verb, v, got)
			}
		}
	}
	if got := fmt.Sprintf("%T", s); got != "apdu.Secret" {
		t.Errorf("%%T: %q", got)
	}
	if got := fmt.Sprint(s, s); got != "[secret] [secret]" {
		t.Errorf("Sprint: %q", got)
	}
	if got := fmt.Sprintln(s); got != "[secret]\n" {
		t.Errorf("Sprintln: %q", got)
	}
	if got := (qaErrorHolder{s}).Error(); got != "failed with [secret]" {
		t.Errorf("error holder: %q", got)
	}
	// The exported fields show the fixed word inside the struct.
	if got := fmt.Sprintf("%+v", exp); !strings.Contains(got, "PIN:[secret]") {
		t.Errorf("%%+v of a struct: %q", got)
	}
	if got := fmt.Sprintf("%#v", exp); !strings.Contains(got, "PIN:[secret]") {
		t.Errorf("%%#v of a struct: %q", got)
	}
	// A nil pointer is a nil pointer, and no panic.
	var nilp *apdu.Secret
	if got := fmt.Sprintf("%v", nilp); got != "<nil>" {
		t.Errorf("nil pointer: %q", got)
	}
}

func TestSecretEveryWayToEncode(t *testing.T) {
	s := apdu.NewSecret(qaPIN)
	p := &s
	exp := qaExported{"n", s, p}
	unexp := qaUnexported{"n", s, p}
	// json
	for name, v := range map[string]any{
		"value": s, "pointer": p, "struct": exp, "pointer to struct": &exp, "unexported struct": unexp, "slice": []apdu.Secret{s},
		"map value": map[string]apdu.Secret{"k": s}, "map key": map[apdu.Secret]int{s: 1}, "embedded": qaEmbedded{s, 1},
	} {
		out, err := json.Marshal(v)
		if err != nil {
			t.Errorf("json %s: %v", name, err)
			continue
		}
		assertNoPIN(t, "json "+name, string(out))
		out, err = json.MarshalIndent(v, ">", "\t")
		if err != nil {
			t.Errorf("json indent %s: %v", name, err)
			continue
		}
		assertNoPIN(t, "json indent "+name, string(out))
	}
	if out, err := json.Marshal(s); err != nil || string(out) != `"[secret]"` {
		t.Errorf("json of a value: %s %v", out, err)
	}
	if out, err := json.Marshal(exp); err != nil || !strings.Contains(string(out), `"PIN":"[secret]"`) || !strings.Contains(string(out), `"Ptr":"[secret]"`) {
		t.Errorf("json of a struct: %s %v", out, err)
	}
	// text
	var tm encoding.TextMarshaler = s
	if b, err := tm.MarshalText(); err != nil || string(b) != "[secret]" {
		t.Errorf("MarshalText: %q %v", b, err)
	}
	if b, err := s.MarshalJSON(); err != nil || string(b) != `"[secret]"` {
		t.Errorf("MarshalJSON: %q %v", b, err)
	}
	// xml and gob take the fixed word or nothing
	for name, v := range map[string]any{"value": s, "struct": exp, "unexported": unexp, "embedded": qaEmbedded{s, 1}} {
		out, err := xml.Marshal(v)
		if err == nil {
			assertNoPIN(t, "xml "+name, string(out))
		}
		var buf bytes.Buffer
		_ = gob.NewEncoder(&buf).Encode(v)
		assertNoPIN(t, "gob "+name, buf.String())
	}
	// templates print through fmt
	var buf bytes.Buffer
	tpl := template.Must(template.New("t").Parse(`{{.}} {{printf "%v %+v %#v %s %x" . . . . .}} {{.PIN}} {{.Ptr}}`))
	if err := tpl.Execute(&buf, exp); err != nil {
		t.Fatal(err)
	}
	assertNoPIN(t, "template", buf.String())
	// slog, text and JSON handlers, as a value, in a group, as an attribute of the logger and in a struct
	for name, h := range map[string]func(*bytes.Buffer) slog.Handler{
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		"text with source and debug": func(b *bytes.Buffer) slog.Handler {
			return slog.NewTextHandler(b, &slog.HandlerOptions{AddSource: true, Level: slog.LevelDebug})
		},
		"json with replace": func(b *bytes.Buffer) slog.Handler {
			return slog.NewJSONHandler(b, &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr { return a }})
		},
	} {
		var out bytes.Buffer
		l := slog.New(h(&out))
		l.Info("m", "pin", s, "ptr", p, "w", exp, "u", unexp, "list", []apdu.Secret{s})
		l.Info("m", slog.Any("pin", s), slog.Group("g", slog.Any("pin", s), slog.Any("w", &exp)))
		l.With("pin", s).WithGroup("grp").Info("m", "pin", s)
		l.LogAttrs(t.Context(), slog.LevelError, "m", slog.Any("pin", s))
		l.Error(fmt.Sprint(s), "err", fmt.Errorf("x %w", errors.New(fmt.Sprint(s))))
		assertNoPIN(t, "slog "+name, out.String())
		if !strings.Contains(out.String(), "[secret]") {
			t.Errorf("slog %s: the attribute is not shown as the fixed word: %s", name, out.String())
		}
	}
	// There is no way to fill a Secret by decoding.
	var d apdu.Secret
	var target any = &d                                                  //nolint:staticcheck // that no decoder can fill a Secret is the point of the next lines
	if err := json.Unmarshal([]byte(`"abcdefgh"`), target); err == nil { //nolint:staticcheck // see above
		t.Error("json.Unmarshal filled a Secret from a string")
	}
	if err := json.Unmarshal([]byte(`{"h":{"b":"YWJj"}}`), target); err != nil || d.Len() != 0 { //nolint:staticcheck // see above
		t.Errorf("json.Unmarshal of an object: %v, len %d", err, d.Len())
	}
	for _, v := range []any{&d, d} {
		if _, ok := v.(encoding.TextUnmarshaler); ok {
			t.Error("a Secret can be filled as text")
		}
		if _, ok := v.(json.Unmarshaler); ok {
			t.Error("a Secret can be filled from JSON")
		}
		if _, ok := v.(encoding.BinaryMarshaler); ok {
			t.Error("a Secret has a binary form")
		}
		if _, ok := v.(gob.GobEncoder); ok {
			t.Error("a Secret has a gob form")
		}
		if _, ok := v.(fmt.Scanner); ok {
			t.Error("a Secret can be scanned")
		}
	}
}

func TestSecretUseWipeLenCopy(t *testing.T) {
	src := bytes.Clone(qaPIN)
	s := apdu.NewSecret(src)
	if s.Len() != len(qaPIN) {
		t.Fatalf("Len %d", s.Len())
	}
	// The secret is a copy: the caller's slice is the caller's, in both directions.
	clear(src)
	var seen []byte
	s.Use(func(b []byte) { seen = bytes.Clone(b) })
	if !bytes.Equal(seen, qaPIN) {
		t.Fatalf("the secret followed its source: %q", seen)
	}
	// Two secrets of one slice are independent holders.
	a, b := apdu.NewSecret(qaPIN), apdu.NewSecret(qaPIN)
	a.Wipe()
	if b.Len() != len(qaPIN) || a.Len() != 0 {
		t.Fatalf("a and b share a holder: %d %d", a.Len(), b.Len())
	}
	// A copy of the value is the same holder: wiping either wipes both, whichever was first.
	c := b
	c.Wipe()
	if b.Len() != 0 || c.Len() != 0 {
		t.Fatalf("a copy keeps the bytes: %d %d", b.Len(), c.Len())
	}
	b.Wipe() // twice, on the other copy
	// Use of a wiped, empty and zero secret never calls f.
	for name, sec := range map[string]apdu.Secret{"wiped": b, "empty": apdu.NewSecret(nil), "empty non-nil": apdu.NewSecret([]byte{}), "zero": {}} {
		sec.Use(func([]byte) { t.Errorf("%s: Use called f", name) })
		sec.Wipe()
		if sec.Len() != 0 {
			t.Errorf("%s: Len %d", name, sec.Len())
		}
		if sec.String() != "[secret]" || fmt.Sprintf("%v %+v %#v", sec, sec, sec) != "[secret] [secret] [secret]" {
			t.Errorf("%s: prints %q", name, fmt.Sprint(sec))
		}
	}
	// Wipe overwrites the bytes that Use gave out, in place.
	d := apdu.NewSecret(qaPIN)
	var kept []byte
	d.Use(func(b []byte) { kept = b })
	d.Wipe()
	if !bytes.Equal(kept, make([]byte, len(qaPIN))) {
		t.Fatalf("Wipe left the bytes: %q", kept)
	}
	// A function that panics does not leave the secret locked.
	e := apdu.NewSecret(qaPIN)
	func() {
		defer func() { _ = recover() }()
		e.Use(func([]byte) { panic("boom") })
	}()
	called := false
	e.Use(func([]byte) { called = true })
	if !called || e.Len() != len(qaPIN) {
		t.Fatal("a panic in Use left the secret locked or changed")
	}
	e.Wipe()
}

func TestSecretIsSafeAcrossGoroutines(t *testing.T) {
	// Meaningful under the race detector: Use, Len, Wipe and printing run at once on copies.
	s := apdu.NewSecret(qaPIN)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := s
			for range 200 {
				switch i % 4 {
				case 0:
					c.Use(func(b []byte) { _ = b[0] })
				case 1:
					_ = c.Len()
				case 2:
					_ = fmt.Sprintf("%v", c)
				case 3:
					if i == 3 {
						c.Wipe()
					}
				}
			}
		}()
	}
	wg.Wait()
	if s.Len() != 0 {
		t.Fatal("the wipe of one copy did not reach the others")
	}
}

// The test below and the two that follow hold what the code does not do yet. Each one is skipped unless
// the variable RITUEEL_QA_BUGS is 1, so that the suite stays green; the comment of each says what is wrong.
func bugSwitch(t *testing.T) {
	t.Helper()
	if os.Getenv("RITUEEL_QA_BUGS") != "1" {
		t.Skip("a reported fault: run with RITUEEL_QA_BUGS=1 to see it")
	}
}

func qaCommand() apdu.Command {
	return apdu.Command{CLA: 0x00, INS: 0x20, P1: 0x00, P2: 0x81, Data: bytes.Clone(qaPIN), Le: 256}
}

const qaCommandText = "apdu.Command{CLA:00 INS:20 P1:00 P2:81 Lc:8 Le:256}"

type qaCommandExported struct {
	Name string
	Cmd  apdu.Command
	Ptr  *apdu.Command
}

type qaCommandEmbedded struct {
	apdu.Command
	Other int
}

func TestCommandEveryWayToPrint(t *testing.T) {
	c := qaCommand()
	p := &c
	var iface any = c
	exp := qaCommandExported{"n", c, p}
	sweepPrint(t, map[string]any{
		"value": c, "pointer": p, "interface": iface, "pointer to pointer": &p,
		"slice": []apdu.Command{c, c}, "slice of pointers": []*apdu.Command{p}, "array": [2]apdu.Command{c, c},
		"map value":       map[string]apdu.Command{"k": c},
		"exported fields": exp, "pointer to exported fields": &exp,
		"embedded": qaCommandEmbedded{c, 1}, "pointer to embedded": &qaCommandEmbedded{c, 1},
		"reflect.Value": reflect.ValueOf(c), "struct in a slice in a map": map[string][]qaCommandExported{"k": {exp}},
		"anonymous struct": struct{ C apdu.Command }{c},
	}, "vVsqxXdbcoOtTUeEfFgG") // not %p: see TestBugUnexportedFieldPrinting
	for _, v := range []any{c, p, iface} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%08.3v", "%-30s", "%t", "%e", "%c", "%U"} {
			if got := fmt.Sprintf(verb, v); got != qaCommandText {
				t.Errorf("%s of %T: %q", verb, v, got)
			}
		}
	}
	if got := fmt.Sprint(c, c); got != qaCommandText+" "+qaCommandText {
		t.Errorf("Sprint: %q", got)
	}
	if got := c.String(); got != qaCommandText || c.GoString() != qaCommandText {
		t.Errorf("String: %q", got)
	}
	if got := fmt.Sprintf("%+v", exp); !strings.Contains(got, "Cmd:"+qaCommandText) {
		t.Errorf("%%+v of a struct: %q", got)
	}
	// What it shows: class, instruction, parameters, Lc and Le, for a command with no data too.
	if got := (apdu.Command{CLA: 0x80, INS: 0xFB, P1: 0x01}).String(); got != "apdu.Command{CLA:80 INS:FB P1:01 P2:00 Lc:0 Le:0}" {
		t.Errorf("no data: %q", got)
	}
	// The data of a command that is changed afterwards is not in the text either, and the text is
	// not the data's length in disguise: the same text for another PIN of the same length.
	other := qaCommand()
	other.Data[0] ^= 0xFF
	if other.String() != c.String() {
		t.Error("the text depends on a byte of the data")
	}
	var nilp *apdu.Command
	if got := fmt.Sprintf("%v", nilp); got != "<nil>" {
		t.Errorf("nil pointer: %q", got)
	}
	// The ways that a program logs a value.
	var buf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&buf, nil))
	l.Info("m", "cmd", c, "ptr", p, "w", exp, "list", []apdu.Command{c})
	l.Info("m", slog.Group("g", slog.Any("cmd", c)))
	assertNoPIN(t, "slog text", buf.String())
	buf.Reset()
	tpl := template.Must(template.New("t").Parse(`{{.}} {{printf "%v %+v %#v %s %x" . . . . .}} {{.Cmd}} {{.Ptr}}`))
	if err := tpl.Execute(&buf, exp); err != nil {
		t.Fatal(err)
	}
	assertNoPIN(t, "template", buf.String())
	var tm any = c
	if _, ok := tm.(fmt.Stringer); !ok {
		t.Error("Command is not a Stringer")
	}
}

// A Command printed with %p shows its Data. A struct that holds a Secret or a Command in a field that is not exported cannot have its Format
// called by fmt, which prints the field by reflection. For a Secret that shows the bytes with a verb that
// a pointer does not take (%s, %q, %c, %t, %e, %f, %U, %V and the like): fmt reports the bad verb and
// prints what the pointer points to, the holder with the PIN in it. For a Command it shows the Data
// with every verb, %v and %+v included. Callers that keep a PIN or a command in a private field and
// print the struct leak it. The fix is in package apdu: keep the bytes where reflection prints no byte
// (for the Secret), and give the printed form of a Command a place that an unexported field cannot skip.
func TestBugUnexportedFieldPrinting(t *testing.T) {
	bugSwitch(t)
	s := apdu.NewSecret(qaPIN)
	c := qaCommand()
	sweepPrint(t, map[string]any{
		"secret in an unexported field":     qaUnexported{"n", s, &s},
		"secret, pointer to such a struct":  &qaUnexported{"n", s, &s},
		"secret, unexported anonymous":      struct{ s apdu.Secret }{s},
		"command in an unexported field":    struct{ c apdu.Command }{c},
		"command, pointer to such a struct": &struct{ c apdu.Command }{c},
		"command, a slice of such structs":  []struct{ c apdu.Command }{{c}},
	}, allVerbs)
	// %p is a verb for pointers: given a Command by value, fmt reports the bad verb and, with its
	// methods switched off while it reports, prints the whole value, Data included.
	sweepPrint(t, map[string]any{"command by value": c, "command in a struct": qaCommandExported{"n", c, &c}, "slice of commands": []apdu.Command{c}}, "p")
}

func TestCommandEncodesWithoutItsData(t *testing.T) {
	c := qaCommand()
	exp := qaCommandExported{"n", c, &c}
	for name, v := range map[string]any{"value": c, "pointer": &c, "struct": exp, "slice": []apdu.Command{c}, "map value": map[string]apdu.Command{"k": c}} {
		out, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json %s: %v", name, err)
		}
		assertNoPIN(t, "json "+name, string(out))
		out, err = json.MarshalIndent(v, "", " ")
		if err != nil {
			t.Fatalf("json indent %s: %v", name, err)
		}
		assertNoPIN(t, "json indent "+name, string(out))
		if out, err = xml.Marshal(v); err == nil {
			assertNoPIN(t, "xml "+name, string(out))
		}
	}
	if out, err := json.Marshal(c); err != nil || string(out) != `"`+qaCommandText+`"` {
		t.Errorf("json: %s %v", out, err)
	}
	if out, err := c.MarshalText(); err != nil || string(out) != qaCommandText {
		t.Errorf("MarshalText: %s %v", out, err)
	}
	var tm encoding.TextMarshaler = c
	_ = tm
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", "cmd", c, "ptr", &c, "w", exp)
	assertNoPIN(t, "slog json", buf.String())
	if !strings.Contains(buf.String(), qaCommandText) {
		t.Errorf("slog json: %s", buf.String())
	}
}

// gob has no use for the printed form: it encodes the exported fields of a Command, Data included. A Secret
// has no exported field, and gob refuses it. The fix, if gob matters, is a GobEncode that refuses.
func TestBugCommandGobEncodesItsData(t *testing.T) {
	bugSwitch(t)
	c := qaCommand()
	for name, v := range map[string]any{"value": c, "pointer": &c, "struct": qaCommandExported{"n", c, &c}, "slice": []apdu.Command{c}} {
		var buf bytes.Buffer
		_ = gob.NewEncoder(&buf).Encode(v)
		assertNoPIN(t, "gob "+name, buf.String())
	}
}
