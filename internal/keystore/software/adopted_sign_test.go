package software

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	// every hash that crypto.Hash names must be linked in for Size to answer
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha3"
	_ "crypto/sha512"
)

// The guards of AdoptedKey.Sign, one by one, and what an accepted signature is checked against: the
// standard library, with the public key that the key gives.

// adFailingReader is a reader that must never be needed: Sign ignores its io.Reader argument.
type adFailingReader struct{}

func (adFailingReader) Read([]byte) (int, error) { return 0, errors.New("no randomness here") }

// adPanicOpts is an option whose method panics: a guard that calls it would panic.
type adPanicOpts struct{}

func (*adPanicOpts) HashFunc() crypto.Hash { panic("HashFunc was called") }

// adOwnOpts is an option of a type of its own that names a hash.
type adOwnOpts crypto.Hash

func (o adOwnOpts) HashFunc() crypto.Hash { return crypto.Hash(o) }

// hashes are every hash that the standard library names, with Size.
func adHashes() []crypto.Hash {
	var out []crypto.Hash
	for h := crypto.MD4; h <= crypto.BLAKE2b_512; h++ {
		out = append(out, h)
	}
	return out
}

func adAllowedHash(h crypto.Hash) bool {
	return h == crypto.SHA256 || h == crypto.SHA384 || h == crypto.SHA512
}

func TestAnAdoptedKeyAcceptsExactlyTheOptionsOfItsAlgorithm(t *testing.T) {
	lowWork(t)
	for _, name := range []string{"rsa4096", "p384"} {
		t.Run(name, func(t *testing.T) {
			k, _ := adOpen(t, name)
			lengths := []int{0, 1, 16, 19, 20, 27, 28, 31, 32, 33, 47, 48, 49, 63, 64, 65, 128}
			for _, h := range adHashes() {
				sizes := append([]int{h.Size()}, lengths...)
				for _, n := range sizes {
					digest := make([]byte, n)
					_, _ = rand.Read(digest)
					sig, err := k.Sign(rand.Reader, digest, h)
					what := fmt.Sprintf("hash %d with a digest of %d bytes", h, n)
					if adAllowedHash(h) && n == h.Size() {
						if err != nil || len(sig) == 0 {
							t.Errorf("%s: %v", what, err)
							continue
						}
						verifies := false
						switch pub := k.Public().(type) {
						case *rsa.PublicKey:
							verifies = rsa.VerifyPKCS1v15(pub, h, digest, sig) == nil
						case *ecdsa.PublicKey:
							verifies = ecdsa.VerifyASN1(pub, digest, sig)
						}
						if !verifies {
							t.Errorf("%s: the signature does not verify with the standard library", what)
						}
						continue
					}
					if !errors.Is(err, ErrParams) || sig != nil {
						t.Errorf("%s: %v, want ErrParams and no signature", what, err)
					}
				}
			}
			d256, d384, d512 := make([]byte, 32), make([]byte, 48), make([]byte, 64)
			others := map[string]crypto.SignerOpts{
				"no options":                      nil,
				"a typed nil PSS option":          (*rsa.PSSOptions)(nil),
				"a PSS option, SHA-256":           &rsa.PSSOptions{Hash: crypto.SHA256},
				"a PSS option with a salt":        &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash},
				"a PSS option with no hash":       &rsa.PSSOptions{},
				"an Ed25519 option":               &ed25519.Options{Hash: crypto.Hash(0)},
				"an Ed25519 option with a hash":   &ed25519.Options{Hash: crypto.SHA256},
				"a typed nil Ed25519 option":      (*ed25519.Options)(nil),
				"a type of its own, SHA-256":      adOwnOpts(crypto.SHA256),
				"a type of its own, no hash":      adOwnOpts(0),
				"an option that panics":           &adPanicOpts{},
				"a typed nil that would panic":    (*adPanicOpts)(nil),
				"a hash that is not a hash":       crypto.Hash(255),
				"the hash of no length":           crypto.Hash(0),
				"a pointer to a crypto.Hash":      new(crypto.Hash),
				"SHA-512/256, which has a digest": crypto.SHA512_256,
			}
			for what, opts := range others {
				for _, digest := range [][]byte{d256, d384, d512} {
					sig, err := k.Sign(rand.Reader, digest, opts)
					if !errors.Is(err, ErrParams) || sig != nil {
						t.Errorf("%s with a digest of %d bytes: %v, want ErrParams and no signature", what, len(digest), err)
					}
				}
			}
			// a key that refused all of that signs still, and ignores the reader
			for _, r := range []io.Reader{nil, adFailingReader{}, rand.Reader} {
				if sig, err := k.Sign(r, d256, crypto.SHA256); err != nil || len(sig) == 0 {
					t.Errorf("the key does not sign after its refusals: %v", err)
				}
			}
		})
	}
}

func TestAnEd25519AdoptedKeySignsTheMessageAsItIsGiven(t *testing.T) {
	lowWork(t)
	k, _ := adOpen(t, "ed25519")
	pub := k.Public().(ed25519.PublicKey)
	for _, msg := range [][]byte{{}, nil, {0}, []byte("a message"), bytes.Repeat([]byte("m"), 1<<16)} {
		sig, err := k.Sign(rand.Reader, msg, crypto.Hash(0))
		if err != nil || !ed25519.Verify(pub, msg, sig) {
			t.Errorf("a message of %d bytes: %v", len(msg), err)
		}
		again, err := k.Sign(adFailingReader{}, msg, crypto.Hash(0))
		if err != nil || !bytes.Equal(sig, again) {
			t.Errorf("Ed25519 is deterministic and the reader is ignored: %v", err)
		}
	}
	msg := bytes.Repeat([]byte{7}, 64)
	others := map[string]crypto.SignerOpts{
		"no options":                       nil,
		"a typed nil Ed25519 option":       (*ed25519.Options)(nil),
		"an empty Ed25519 option":          &ed25519.Options{},
		"Ed25519ph":                        &ed25519.Options{Hash: crypto.SHA512},
		"Ed25519ctx":                       &ed25519.Options{Context: "a context"},
		"Ed25519ph with a context":         &ed25519.Options{Hash: crypto.SHA512, Context: "a context"},
		"a type of its own naming no hash": adOwnOpts(0),
		"a PSS option":                     &rsa.PSSOptions{},
		"a typed nil PSS option":           (*rsa.PSSOptions)(nil),
		"an option that panics":            &adPanicOpts{},
		"a typed nil that would panic":     (*adPanicOpts)(nil),
		"crypto.Hash(255)":                 crypto.Hash(255),
		"a pointer to a crypto.Hash":       new(crypto.Hash),
	}
	for _, h := range adHashes() {
		others[fmt.Sprintf("hash %d", h)] = h
	}
	for what, opts := range others {
		sig, err := k.Sign(rand.Reader, msg, opts)
		if !errors.Is(err, ErrParams) || sig != nil {
			t.Errorf("%s: %v, want ErrParams and no signature", what, err)
		}
	}
}

func TestAnAdoptedKeyGivesAPublicKeyThatIsNeverItsOwn(t *testing.T) {
	lowWork(t)
	for _, name := range []string{"ed25519", "p384", "rsa4096"} {
		t.Run(name, func(t *testing.T) {
			k, _ := adOpen(t, name)
			first, keep := k.Public(), k.Public()
			switch pub := first.(type) {
			case ed25519.PublicKey:
				pub[0] ^= 0xFF
			case *rsa.PublicKey:
				pub.N.SetInt64(15)
				pub.E = 3
			case *ecdsa.PublicKey:
				*pub = ecdsa.PublicKey{}
			}
			second := k.Public()
			if eq, ok := second.(interface{ Equal(crypto.PublicKey) bool }); !ok || !eq.Equal(keep) {
				t.Fatalf("a change of the public key that was handed out reached the key")
			}
			signAndVerify(t, k)
			if k.Public() == nil {
				t.Errorf("no public key")
			}
		})
	}
}

func TestAnAdoptedKeyRefusesToSignAfterCloseAndClosesOnce(t *testing.T) {
	lowWork(t)
	for _, name := range []string{"ed25519", "p384", "rsa4096"} {
		t.Run(name, func(t *testing.T) {
			k, s := adOpen(t, name)
			fp := k.Fingerprint()
			if err := k.Close(); err != nil {
				t.Fatal(err)
			}
			if err := k.Close(); err != nil {
				t.Errorf("a second Close: %v", err)
			}
			in, opts := make([]byte, 32), crypto.SignerOpts(crypto.SHA256)
			switch name {
			case "p384":
				in, opts = make([]byte, 48), crypto.SHA384
			case "ed25519":
				opts = crypto.Hash(0)
			}
			sig, err := k.Sign(rand.Reader, in, opts)
			if !errors.Is(err, ErrParams) || sig != nil {
				t.Errorf("Sign after Close: %v, want ErrParams", err)
			}
			if k.Public() != nil {
				t.Errorf("a public key after Close")
			}
			// what the key says of itself is kept, as the contract says
			if k.Fingerprint() != fp || fp != s.fk.Primary.Fingerprint || k.Algorithm() != s.fk.Primary.Algorithm || !k.Created().Equal(s.fk.Primary.Created) {
				t.Errorf("the key does not say what it is after Close")
			}
		})
	}
}

func TestAnAdoptedKeySignsAndClosesFromSeveralGoroutines(t *testing.T) {
	lowWork(t)
	for _, name := range []string{"ed25519", "p384"} {
		t.Run(name, func(t *testing.T) {
			k, _ := adOpen(t, name)
			in, opts := []byte("a message"), crypto.SignerOpts(crypto.Hash(0))
			if name == "p384" {
				in, opts = make([]byte, 48), crypto.SHA384
			}
			pub := k.Public()
			var wg sync.WaitGroup
			var signed, refused, bad atomic.Int64
			start := make(chan struct{})
			for i := 0; i < 12; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					for j := 0; j < 40; j++ {
						sig, err := k.Sign(rand.Reader, in, opts)
						switch {
						case err == nil && len(sig) > 0:
							ok := false
							switch p := pub.(type) {
							case ed25519.PublicKey:
								ok = ed25519.Verify(p, in, sig)
							case *ecdsa.PublicKey:
								ok = ecdsa.VerifyASN1(p, in, sig)
							}
							if !ok {
								bad.Add(1)
							}
							signed.Add(1)
						case errors.Is(err, ErrParams) && sig == nil:
							refused.Add(1)
						default:
							bad.Add(1)
						}
						_ = k.Public()
						_ = k.Fingerprint()
					}
				}()
			}
			for i := 0; i < 3; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					if err := k.Close(); err != nil {
						bad.Add(1)
					}
				}()
			}
			close(start)
			wg.Wait()
			if bad.Load() != 0 {
				t.Errorf("%d answers were neither a good signature nor a refusal", bad.Load())
			}
			if signed.Load()+refused.Load() != 12*40 {
				t.Errorf("%d signatures and %d refusals, want %d answers", signed.Load(), refused.Load(), 12*40)
			}
			if _, err := k.Sign(nil, in, opts); !errors.Is(err, ErrParams) {
				t.Errorf("Sign after all the Closes: %v", err)
			}
		})
	}
}
