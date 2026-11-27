package openpgpapp

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/smartcard/apdu"
)

// qaSink answers 9000 to everything and keeps nothing of what it is given.
type qaSink struct{}

func (qaSink) PowerOn(time.Duration) ([]byte, error)          { return nil, nil }
func (qaSink) PowerOff(time.Duration) error                   { return nil }
func (qaSink) ExtendedAPDU() bool                             { return false }
func (qaSink) Close() error                                   { return nil }
func (qaSink) Transmit([]byte, time.Duration) ([]byte, error) { return []byte{0x90, 0x00}, nil }

// heapCount counts the places of the live heap (as the runtime dumps it, with the stacks) that hold the needle.
func heapCount(t *testing.T, needle []byte) int {
	t.Helper()
	runtime.GC()
	runtime.GC()
	path := filepath.Join(t.TempDir(), "heap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	debug.WriteHeapDump(f.Fd())
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	dump, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Count(dump, needle)
}

// TestNoCopyOfAPINSurvives: a PIN of random bytes goes through the layer (a verification, a change, a
// verification in two sessions), and when the caller has wiped its Secrets and its own slice, the live heap
// holds no copy of it but the one that this test keeps to search with. A copy that the encoding or the
// session keeps (in a variable of a package, a field of the session, an error) shows as a second place.
// While the Secret is not wiped, the heap holds it twice (the search slice and the Secret): the holder is
// the only other place.
func TestNoCopyOfAPINSurvives(t *testing.T) {
	needle := make([]byte, 24)
	if _, err := rand.Read(needle); err != nil {
		t.Fatal(err)
	}
	user, admin := bytes.Clone(needle[:12]), bytes.Clone(needle[12:])
	su, sa := apdu.NewSecret(user), apdu.NewSecret(admin)
	clear(user)
	clear(admin)
	if n := heapCount(t, needle[:12]); n != 2 {
		t.Fatalf("before any use, the user PIN is in %d places, want 2 (the search slice and the holder)", n)
	}
	s, err := NewSession(qaSink{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.selected = true
	var errs []error
	for _, c := range []apdu.Command{
		apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(su),
		apdu.Command{INS: 0x20, P2: 0x83}.WithSecretData(sa),
		apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(su, su),
		apdu.Command{INS: 0x24, P2: 0x83}.WithSecretPair(sa, sa),
		apdu.Command{INS: 0x20, P2: 0x84}.WithSecretData(su), // refused
	} {
		_, err := s.send(c)
		errs = append(errs, err)
	}
	// The same through a lost exchange.
	bad := &qaTransport{script: []qaStep{{err: os.ErrClosed}}}
	_, err = qaSession(t, bad, Options{}, nil).send(apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(su))
	errs = append(errs, err)
	if n := heapCount(t, needle[:12]); n != 2 {
		t.Errorf("after the sends, the user PIN is in %d places, want 2", n)
	}
	su.Wipe()
	sa.Wipe()
	if n := heapCount(t, needle[:12]); n != 1 {
		t.Errorf("after the wipe, the user PIN is in %d places, want 1 (the search slice)", n)
	}
	if n := heapCount(t, needle[12:]); n != 1 {
		t.Errorf("after the wipe, the Admin PIN is in %d places, want 1 (the search slice)", n)
	}
	runtime.KeepAlive(errs)
	runtime.KeepAlive(needle)
}
