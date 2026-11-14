package pki_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"io"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/pki"
)

// Values that are nil inside an interface: the interface is not nil, a method called on it may panic, and the package
// treats it as no value at all. One type for each kind that can be nil.
type (
	readerFunc func([]byte) (int, error)
	readerMap  map[string]int
	readerSl   []byte
	readerChan chan int
)

func (f readerFunc) Read(b []byte) (int, error) {
	if f == nil {
		return 0, io.EOF
	}
	return f(b)
}
func (m readerMap) Read([]byte) (int, error) { return 0, io.EOF }
func (s readerSl) Read([]byte) (int, error)  { return 0, io.EOF }
func (c readerChan) Read([]byte) (int, error) {
	return 0, io.EOF
}

type (
	signerFunc func()
	signerMap  map[string]int
)

func (signerFunc) Public() crypto.PublicKey { panic("Public of a nil signer was called") }
func (signerFunc) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("Sign of a nil signer was called")
}
func (signerMap) Public() crypto.PublicKey { panic("Public of a nil signer was called") }
func (signerMap) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("Sign of a nil signer was called")
}

func typedNilReaders() map[string]io.Reader {
	return map[string]io.Reader{
		"a nil *bytes.Reader":   (*bytes.Reader)(nil),
		"a nil *strings.Reader": (*strings.Reader)(nil),
		"a nil *os.File":        (*os.File)(nil),
		"a nil func":            readerFunc(nil),
		"a nil map":             readerMap(nil),
		"a nil slice":           readerSl(nil),
		"a nil channel":         readerChan(nil),
	}
}

func TestATypedNilSourceOfRandomNumbersIsNoValueAndIsNotCryptoRand(t *testing.T) {
	for name, r := range typedNilReaders() {
		t.Run("NewSerial with "+name, func(t *testing.T) {
			n, err := pki.NewSerial(r)
			refused(t, err, pki.ErrParams)
			if n != nil {
				t.Errorf("a serial %v came: the nil reader was taken for crypto/rand", n)
			}
			if err != nil && !strings.Contains(err.Error(), "nil value") {
				t.Errorf("the text does not say nil: %q", err.Error())
			}
		})
		t.Run("Sign with "+name, func(t *testing.T) {
			s := newOpaque(t)
			sig, err := pki.SignRoot(r, s, rootParams(&s.key.PublicKey), mustRootTBS(t, s.key))
			refused(t, err, pki.ErrParams)
			if sig != nil || s.calls != 0 {
				t.Errorf("a signature came, or the signer was called %d times", s.calls)
			}
		})
	}
	// A reader that is a non-nil empty value of the same kinds is a reader that fails, which is another error.
	t.Run("an empty map that is not nil", func(t *testing.T) {
		_, err := pki.NewSerial(readerMap{})
		refused(t, err, pki.ErrParams)
		if err != nil && strings.Contains(err.Error(), "nil value") {
			t.Errorf("a reader that is not nil is called nil: %q", err.Error())
		}
	})
	t.Run("an empty slice that is not nil", func(t *testing.T) {
		_, err := pki.NewSerial(readerSl{})
		refused(t, err, pki.ErrParams)
		if err != nil && strings.Contains(err.Error(), "nil value") {
			t.Errorf("a reader that is not nil is called nil: %q", err.Error())
		}
	})
}

func TestATypedNilSignerIsNoSignerAndIsNeverCalled(t *testing.T) {
	good := newOpaque(t)
	tbs := mustRootTBS(t, good.key)
	signers := map[string]crypto.Signer{
		"a nil *ecdsa.PrivateKey": (*ecdsa.PrivateKey)(nil),
		"a nil *opaqueSigner":     (*opaqueSigner)(nil),
		"a nil func":              signerFunc(nil),
		"a nil map":               signerMap(nil),
	}
	for name, s := range signers {
		t.Run(name, func(t *testing.T) {
			sig, err := pki.SignRoot(nil, s, rootParams(&good.key.PublicKey), tbs)
			refused(t, err, pki.ErrParams)
			if sig != nil {
				t.Error("a signature came with the error")
			}
			if err != nil && !strings.Contains(err.Error(), "no signer") {
				t.Errorf("the text does not say that there is no signer: %q", err.Error())
			}
		})
	}
	t.Run("a typed nil issuer key of an intermediate", func(t *testing.T) {
		root := buildRoot(t, nil)
		p := root.interParams(withExtensions(t, goodExtensions()...))
		p.IssuerKey = (*ecdsa.PublicKey)(nil)
		tbs, err := intermediateTBS(t, p)
		refused(t, err, pki.ErrParams)
		if tbs != nil {
			t.Error("a body came with the error")
		}
	})
	t.Run("the good signer is still good", func(t *testing.T) {
		if _, err := pki.SignRoot(nil, good, rootParams(&good.key.PublicKey), tbs); err != nil {
			t.Fatal(err)
		}
	})
}

// The count of months is refused before it is added, whatever its size, so that it never wraps to a date that looks
// right. The edges: from the first second that a certificate can hold, the last month that fits and the next; and
// the extremes of the integer.
func TestMonthsThatOverflowNeverWrapToADateInAddMonths(t *testing.T) {
	first := utc(1, 1, 1, 0, 0, 1)
	last := utc(9999, 12, 31, 23, 59, 59)
	cases := []struct {
		name   string
		from   time.Time
		months int
		accept bool
	}{
		{"from the first second, the last month of the years", first, 12*9999 - 1, true},
		{"from the first second, one month more", first, 12 * 9999, false},
		{"from the first second, two months more", first, 12*9999 + 1, false},
		{"from the last second, none", last, 0, false},
		{"from the last second, one month", last, 1, false},
		{"from a second of December 9999, one month", utc(9999, 12, 1, 0, 0, 0), 1, false},
		{"from a second of November 9999, one month", utc(9999, 11, 30, 23, 59, 59), 1, true},
		{"the largest int", ceremony, math.MaxInt, false},
		{"the largest int less one", ceremony, math.MaxInt - 1, false},
		{"the smallest int", ceremony, math.MinInt, false},
		{"the smallest int plus one", ceremony, math.MinInt + 1, false},
		{"the largest int32", ceremony, math.MaxInt32, false},
		{"the smallest int32", ceremony, math.MinInt32, false},
		{"2^32", ceremony, 1 << 32, false},
		{"2^32 plus 13: a count that wraps to 13 in 32 bits", ceremony, 1<<32 + 13, false},
		{"2^62", ceremony, 1 << 62, false},
		{"minus 2^62", ceremony, -(1 << 62), false},
		{"zero", ceremony, 0, false},
		{"minus one", ceremony, -1, false},
		{"minus 12*9999", ceremony, -12 * 9999, false},
		{"one", ceremony, 1, true},
	}
	for _, c := range cases {
		t.Run("AddMonths: "+c.name, func(t *testing.T) {
			got, err := pki.AddMonths(c.from, c.months)
			if err == nil && (got.Year() < 1 || got.Year() > 9999) {
				t.Errorf("a date outside the years that a certificate holds: %v", got)
			}
			if err != nil {
				refused(t, err, pki.ErrParams)
				if !got.IsZero() {
					t.Error("a time came with the error")
				}
			}
			if math.Abs(float64(c.months)) > 12*9999 && err == nil {
				t.Errorf("%d months are accepted: %v", c.months, got)
			}
		})
	}
}
