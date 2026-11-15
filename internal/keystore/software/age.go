package software

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strconv"

	"filippo.io/age"
)

// The work factor of a passphrase file is the N of the scrypt cost 2^N (record 0002, rule 28).
const (
	// MinWorkFactor is the lowest work factor that a file may say: 2^18.
	MinWorkFactor = 18
	// MaxWorkFactor is the highest work factor that a file may say: 2^22, the limit that the age
	// reference code applies by default.
	MaxWorkFactor = 22
	// WriteWorkFactor is the work factor that a file is written with: 18, the default of age and
	// the lowest that the rule allows. A file is read at any factor from [MinWorkFactor] to
	// [MaxWorkFactor], so a later change of this number breaks no old file. The cost is memory and
	// time at every open: about 256 MiB and a second at 18, and about 4 GiB and 7 to 9 seconds at 22.
	WriteWorkFactor = 18
)

// The two variables below are the production limits of the age reader and writer. They are
// variables only so that a test in this package can lower them for the tests that do not need the
// real cost; no code outside a test file sets them.
var (
	// workFactorWritten is the work factor of the files that are written.
	workFactorWritten = WriteWorkFactor
	// workFactorLowest is the lowest work factor that a file may say.
	workFactorLowest = MinWorkFactor
)

// The shape of the one stanza of a passphrase file (age v1; docs/reference/bundle.md, "The software
// root's key files").
const (
	// scryptType is the type of the stanza of a passphrase.
	scryptType = "scrypt"
	// scryptArgs is the number of arguments of the stanza: the salt and the work factor.
	scryptArgs = 2
	// scryptSaltChars is the length of the salt of 16 bytes in unpadded Base64.
	scryptSaltChars = 22
	// scryptBodyLen is the length of the body of the stanza: the 16-byte file key and the 16-byte
	// tag of the AEAD that wraps it.
	scryptBodyLen = 32
	// maxWorkFactorChars is the most characters of a work factor: two digits hold 22.
	maxWorkFactorChars = 2
)

// errHeader is the refusal of a header that is not exactly the header of a passphrase file. It is
// raised before scrypt runs. The words are fixed: nothing of the file is repeated.
func errHeader(why string) error {
	return refuse(ErrKeyFile, "the age header is not exactly one scrypt stanza of the page: %s", why)
}

// checkStanzas is the look at the header of a passphrase file before any work (record 0002, rule
// 28 and its "Why"): exactly one stanza, of the type scrypt, with two arguments, a salt of 16 bytes
// in unpadded Base64 and a work factor as a canonical decimal number from the lowest to the highest
// that a file may say, and the body of the length that the stanza has. Any other stanza, an
// X25519 stanza, an unknown type and a header with no stanza are refused, each as [ErrKeyFile].
func checkStanzas(stanzas []*age.Stanza) error {
	if len(stanzas) != 1 || stanzas[0] == nil {
		return errHeader("the file does not hold exactly one stanza")
	}
	s := stanzas[0]
	if s.Type != scryptType {
		return errHeader("the stanza is not of the type scrypt")
	}
	if len(s.Args) != scryptArgs {
		return errHeader("the stanza has not two arguments")
	}
	if len(s.Args[0]) != scryptSaltChars {
		return errHeader("the salt is not 22 characters of unpadded Base64")
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(s.Args[0])
	if err != nil || len(salt) != 16 {
		return errHeader("the salt is not 16 bytes of unpadded Base64")
	}
	wf, ok := canonicalDecimal(s.Args[1])
	if !ok {
		return errHeader("the work factor is not a canonical decimal number")
	}
	if wf < workFactorLowest || wf > MaxWorkFactor {
		return errHeader("the work factor is outside the range of the page")
	}
	if len(s.Body) != scryptBodyLen {
		return errHeader("the body of the stanza is not 32 bytes")
	}
	return nil
}

// canonicalDecimal reads a number written with the digits 1 to 9 first and then digits, at most
// two of them: no sign, no zero in front, no space, no fraction and no other base.
func canonicalDecimal(s string) (int, bool) {
	if len(s) == 0 || len(s) > maxWorkFactorChars || s[0] < '1' || s[0] > '9' {
		return 0, false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// scryptGate is the identity that the reader hands to age. It checks the stanzas with
// [checkStanzas] and only then hands them to the identity of the library, inner, which does the
// work. A test puts a stub in inner to see that the work is not started.
type scryptGate struct{ inner age.Identity }

// Unwrap checks the header and, when it is the header of the page, unwraps the file key.
func (g scryptGate) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if err := checkStanzas(stanzas); err != nil {
		return nil, err
	}
	if g.inner == nil {
		return nil, refuse(ErrParams, "there is no identity to open the file with")
	}
	return g.inner.Unwrap(stanzas)
}

// errInspected is what the identity of [inspectHeader] returns when the header passed.
var errInspected = errors.New("software: the header was inspected")

// inspector is the identity that looks at the header and does nothing else.
type inspector struct{}

func (inspector) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if err := checkStanzas(stanzas); err != nil {
		return nil, err
	}
	return nil, errInspected
}

// inspectHeader reads the header of an age file and checks it with [checkStanzas]. No scrypt runs
// and no passphrase is needed. A file that does not start with an age header is an [ErrKeyFile].
func inspectHeader(file []byte) error {
	_, err := age.Decrypt(bytes.NewReader(file), inspector{})
	switch {
	case errors.Is(err, errInspected):
		return nil
	case errors.Is(err, ErrKeyFile):
		return err
	}
	// The text of the library holds lines of the file, so it is not repeated.
	return refuse(ErrKeyFile, "the file is not an age file of the page")
}

// secretFormat is a format that needs the passphrase of the key that a file holds. The Store asks
// the source once for a key and hands the passphrase to each of the calls of one save or one open.
type secretFormat interface {
	// inspect looks at the header of a file before a passphrase is asked.
	inspect(file []byte) error
	// wrapWith returns the bytes of the file for a payload.
	wrapWith(pass []byte, kind FileKind, payload []byte) ([]byte, error)
	// unwrapWith returns the payload of a file, which has passed the check of its size and mode.
	unwrapWith(pass []byte, kind FileKind, file []byte) ([]byte, error)
}

// ageFormat is the format of a passphrase root: an age file, binary, with one scrypt recipient and
// no other stanza (record 0002, rules 20 and 22). It implements [format] only to be held in the
// same field: its own methods have no passphrase and refuse.
type ageFormat struct{}

var (
	_ format       = ageFormat{}
	_ secretFormat = ageFormat{}
)

func (ageFormat) wrap(FileKind, []byte) ([]byte, error) {
	return nil, refuse(ErrParams, "an age file is written with the passphrase of its key")
}

func (ageFormat) unwrap(FileKind, []byte) ([]byte, error) {
	return nil, refuse(ErrParams, "an age file is read with the passphrase of its key")
}

func (ageFormat) inspect(file []byte) error {
	if len(file) > MaxKeyFileSize {
		return refuse(ErrKeyFile, "the key file is longer than %d bytes", MaxKeyFileSize)
	}
	return inspectHeader(file)
}

// kindOK reports whether kind is one of the four kinds of file.
func kindOK(kind FileKind) bool {
	switch kind {
	case FileX509, FileOpenPGP, FileRevocation, FileRemoval:
		return true
	}
	return false
}

// wrapWith encrypts the payload to the passphrase with the work factor [WriteWorkFactor]. It looks
// at the header of its own output with the check of the reader before it returns the file. The
// library takes the passphrase as a string and keeps a copy of its own: neither can be cleared.
func (ageFormat) wrapWith(pass []byte, kind FileKind, payload []byte) ([]byte, error) {
	if !kindOK(kind) {
		return nil, refuse(ErrParams, "the kind of file is not one of the four")
	}
	if len(payload) == 0 || len(payload) > MaxKeyFileSize {
		return nil, refuse(ErrKeyFile, "the payload is empty or longer than %d bytes", MaxKeyFileSize)
	}
	wf := workFactorWritten
	if wf < 1 || wf > MaxWorkFactor {
		return nil, refuse(ErrParams, "the work factor that is written is outside the range")
	}
	rcp, err := age.NewScryptRecipient(string(pass))
	if err != nil {
		return nil, refuse(ErrPassphrase, "the passphrase is empty")
	}
	rcp.SetWorkFactor(wf)
	out := bytes.NewBuffer(make([]byte, 0, len(payload)+1024))
	w, err := age.Encrypt(out, rcp)
	if err != nil {
		return nil, refuse(ErrKeyFile, "the age file could not be written")
	}
	if _, err := w.Write(payload); err != nil {
		return nil, refuse(ErrKeyFile, "the age file could not be written")
	}
	if err := w.Close(); err != nil {
		return nil, refuse(ErrKeyFile, "the age file could not be written")
	}
	file := out.Bytes()
	if err := inspectHeader(file); err != nil {
		clear(file)
		return nil, err
	}
	return file, nil
}

// unwrapWith decrypts a file with the passphrase. The header is looked at first (no scrypt runs for
// a header that is refused); then the library opens the file through [scryptGate] with the highest
// work factor at [MaxWorkFactor]. The payload is read up to [MaxKeyFileSize] and one byte more;
// a longer payload is refused. A file that did not open with the passphrase is an
// [ErrWrongPassphrase]; a file that is damaged, cut or longer than it says is an [ErrKeyFile].
func (f ageFormat) unwrapWith(pass []byte, kind FileKind, file []byte) ([]byte, error) {
	if !kindOK(kind) {
		return nil, refuse(ErrParams, "the kind of file is not one of the four")
	}
	if err := f.inspect(file); err != nil {
		return nil, err
	}
	id, err := age.NewScryptIdentity(string(pass))
	if err != nil {
		return nil, refuse(ErrPassphrase, "the passphrase is empty")
	}
	id.SetMaxWorkFactor(MaxWorkFactor)
	r, err := age.Decrypt(bytes.NewReader(file), scryptGate{inner: id})
	if err != nil {
		return nil, classifyDecrypt(err)
	}
	buf := make([]byte, MaxKeyFileSize+1)
	defer clear(buf)
	n, err := readPayload(r, buf)
	if err != nil {
		return nil, err
	}
	// This cannot be reached: inspect holds a file to MaxKeyFileSize and a payload is shorter.
	if n > MaxKeyFileSize {
		return nil, refuse(ErrKeyFile, "the payload is longer than %d bytes", MaxKeyFileSize)
	}
	if n == 0 {
		return nil, refuse(ErrKeyFile, "the payload is empty")
	}
	return bytes.Clone(buf[:n]), nil
}

// classifyDecrypt turns an error of age.Decrypt into one of the package: a refusal of the gate is
// its own; a passphrase that did not match is an [ErrWrongPassphrase]; anything else (a header
// that does not parse, a header MAC that is wrong, no nonce) is a damaged file. The text of the
// library is never repeated: it holds lines of the file.
func classifyDecrypt(err error) error {
	var none *age.NoIdentityMatchError
	switch {
	case errors.Is(err, ErrKeyFile), errors.Is(err, ErrParams):
		return err
	case errors.As(err, &none):
		return refuse(ErrWrongPassphrase, "the file did not open with the passphrase")
	}
	return refuse(ErrKeyFile, "the age file is damaged")
}

// readPayload reads the decrypted payload into buf, which is one byte longer than the limit, and
// returns how many bytes it read. An end that is not the clean end of the stream (a cut, a changed
// byte, data after the last chunk) is an [ErrKeyFile].
func readPayload(r io.Reader, buf []byte) (int, error) {
	n, empty := 0, 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			clear(buf[:n])
			return 0, refuse(ErrKeyFile, "the payload is damaged or cut")
		}
		if m == 0 {
			if empty++; empty >= maxEmptyReads {
				clear(buf[:n])
				return 0, refuse(ErrKeyFile, "the payload does not end")
			}
			continue
		}
		empty = 0
	}
	return n, nil
}
