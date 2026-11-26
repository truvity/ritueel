package port

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/atoom/common/refusal"
	keyv1alpha1 "github.com/truvity/atoom/key/gen/atoom/key/v1alpha1"
	"github.com/truvity/atoom/key/gen/atoom/key/v1alpha1/keyv1alpha1connect"
	"github.com/truvity/atoom/key/purpose"
	"github.com/truvity/atoom/key/signer"

	"ritueel.id/ritueel/internal/keystore"
)

// Client is the generated client of the key port.
type Client = keyv1alpha1connect.KeyStoreServiceClient

// callTimeout is the deadline of each call of the port that this package makes. A key in a file answers
// at once; a store that waits for a person is for a later step, which sets its own.
const callTimeout = time.Minute

// The refusals of this package. A refusal of the port itself is the Connect error of the port, wrapped.
var (
	// ErrUnknownStore marks a key store that the table of [Describe] does not hold.
	ErrUnknownStore = errors.New("port: the key store is not one that ritueel knows")
	// ErrKeyExists marks a key that exists already: the purpose has a key before a birth, or the store
	// did not make the key that a birth asked for. An existing key is never adopted.
	ErrKeyExists = errors.New("port: a key of the purpose exists already")
	// ErrBirth marks a birth that did not give the key that it asked for: the public key does not read back
	// as the one that was made, or a signature does not verify.
	ErrBirth = errors.New("port: the key that was made is not the key that was asked for")
	// ErrAlgorithm marks a purpose that is not ES384, the algorithm of a root key.
	ErrAlgorithm = errors.New("port: the purpose is not an ES384 key")
	// ErrClosed marks a call on a key that was closed.
	ErrClosed = errors.New("port: the key is closed")
)

// Info says what a key store is, for the engine: its kind, whether a key of it can be copied, and the
// warning codes that a ceremony record carries for it.
type Info struct {
	// Store is the name that the store gives itself in Capabilities.
	Store string
	// Kind is where a key of the store lives: the member `store` of root.json.
	Kind keystore.Kind
	// Copyable is true when a key of the store can be copied.
	Copyable bool
	// Warnings are the codes for the ceremony record.
	Warnings []string
}

// stores is the one table of the key stores that ritueel knows, by the name that a store gives itself.
var stores = map[string]Info{
	"software": {Store: "software", Kind: keystore.KindSoftware, Copyable: true, Warnings: []string{keystore.WarningSoftwareCopyable}},
}

// Lookup returns the entry of the table for the name that a store gives itself, or false.
func Lookup(store string) (Info, bool) {
	info, ok := stores[store]
	info.Warnings = slices.Clone(info.Warnings)
	return info, ok
}

// Describe asks the store what it is (Capabilities) and returns its entry of the table. A store that the
// table does not hold is an [ErrUnknownStore].
func Describe(ctx context.Context, client Client) (Info, error) {
	if ctx == nil || client == nil {
		return Info{}, errors.New("port: Describe needs a context and a client")
	}
	info, _, err := capabilities(ctx, client)
	return info, err
}

// capabilities asks the store what it is, once: its entry of the table, and the purposes it serves. A
// store that the table does not hold is an [ErrUnknownStore].
func capabilities(ctx context.Context, client Client) (Info, []*keyv1alpha1.PurposeInfo, error) {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	caps, err := client.Capabilities(cctx, connect.NewRequest(&keyv1alpha1.CapabilitiesRequest{}))
	if err != nil {
		return Info{}, nil, fmt.Errorf("port: Capabilities: %w", err)
	}
	info, ok := Lookup(caps.Msg.GetStore())
	if !ok {
		return Info{}, nil, ErrUnknownStore
	}
	return info, caps.Msg.GetPurposes(), nil
}

// checkPurpose refuses a purpose that the store does not serve, that does not allow sign, or that is not an
// ES384 key: the purpose of a root key.
func checkPurpose(purposes []*keyv1alpha1.PurposeInfo, name string) error {
	for _, p := range purposes {
		if p.GetName() != name {
			continue
		}
		if !slices.Contains(p.GetOperations(), string(purpose.Sign)) {
			return signer.ErrOperation
		}
		if p.GetAlgorithm() != purpose.ES384 {
			return ErrAlgorithm
		}
		return nil
	}
	return signer.ErrPurpose
}

// Key is the key of one purpose in a key store, as [keystore.Key]. It is safe for concurrent use.
type Key struct {
	signer *signer.Signer
	info   Info
	pub    *ecdsa.PublicKey

	mu     sync.Mutex
	closed bool
}

var _ keystore.Key = (*Key)(nil)

// NewKey returns the key of a purpose that has a key. It asks the store what it is ([Describe]), and
// the Signer of atoom asks for the purpose, which must allow sign, and for its public key. The purpose
// must be an ES384 key on P-384. ctx is the base of every later call of the key: give it a context that
// lives as long as the key does.
func NewKey(ctx context.Context, client Client, name string) (*Key, error) {
	info, err := Describe(ctx, client)
	if err != nil {
		return nil, err
	}
	s, err := signer.New(ctx, client, name, signer.WithTimeout(callTimeout))
	if err != nil {
		return nil, fmt.Errorf("port: the key of the purpose cannot be opened: %w", err)
	}
	pub, ok := s.Public().(*ecdsa.PublicKey)
	if s.Algorithm() != purpose.ES384 || !ok || pub.Curve != elliptic.P384() {
		return nil, ErrAlgorithm
	}
	return &Key{signer: s, info: info, pub: pub}, nil
}

// Public is the public key of the purpose, an *ecdsa.PublicKey on P-384.
func (k *Key) Public() crypto.PublicKey { return k.pub }

// Sign signs a SHA-384 digest in the store and returns the ASN.1 value of the signature. The Signer of
// atoom has verified the signature with the public key before it is returned. A key that was closed does
// not sign.
func (k *Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	k.mu.Lock()
	closed := k.closed
	k.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}
	sig, err := k.signer.Sign(rand, digest, opts)
	if err != nil {
		return nil, endOfContext(err)
	}
	return sig, nil
}

// endOfContext makes the end of a context that the client of the port reports as a Connect code, canceled
// or deadline_exceeded, an error that errors.Is also finds as context.Canceled or context.DeadlineExceeded.
// Any other error, and one that is already so, is returned as it is.
func endOfContext(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case connect.CodeOf(err) == connect.CodeCanceled:
		return fmt.Errorf("%w: %w", context.Canceled, err)
	case connect.CodeOf(err) == connect.CodeDeadlineExceeded:
		return fmt.Errorf("%w: %w", context.DeadlineExceeded, err)
	}
	return err
}

// Kind is where the key lives, from the table.
func (k *Key) Kind() keystore.Kind { return k.info.Kind }

// Copyable is true when a key of the store can be copied, from the table.
func (k *Key) Copyable() bool { return k.info.Copyable }

// Warnings are the codes for the ceremony record, from the table.
func (k *Key) Warnings() []string { return slices.Clone(k.info.Warnings) }

// Close ends the use of the key: it does not sign after it, and a second Close does nothing. It does not
// end the store, which belongs to whoever started it.
func (k *Key) Close() error {
	k.mu.Lock()
	k.closed = true
	k.mu.Unlock()
	return nil
}

// selfTest is the text that a birth signs and verifies, once.
const selfTest = "ritueel: a key that is born is used once before anything relies on it"

// Birth makes the key of a purpose and gives it back, in four steps (record 0005, rule 10):
//
// Before any call that can make a key, the store is asked what it is: a store that the table does not
// hold ([ErrUnknownStore]) and a purpose that the store does not serve as an ES384 key that allows sign
// are refused with nothing made. Then:
//
//  1. the key must be absent: PublicKey answers that the purpose has no key, and any other answer is
//     an [ErrKeyExists] or a failure;
//  2. Ensure makes the key, and must answer that it made it: a store that answers that the key was there is
//     an [ErrKeyExists], and the key is never adopted;
//  3. PublicKey must give the public key that Ensure gave;
//  4. a signature over a digest must verify with that public key.
//
// A fault of a later step leaves the key in the store: nothing is deleted, and the caller says so. The
// purpose must be declared to the store as an ES384 key that allows sign.
func Birth(ctx context.Context, client Client, name string) (*Key, error) {
	if ctx == nil || client == nil {
		return nil, errors.New("port: Birth needs a context and a client")
	}
	_, purposes, err := capabilities(ctx, client)
	if err != nil {
		return nil, err
	}
	if err := checkPurpose(purposes, name); err != nil {
		return nil, fmt.Errorf("port: the purpose cannot make a root key, and nothing was made: %w", err)
	}
	if _, err := publicKey(ctx, client, name); err == nil {
		return nil, ErrKeyExists
	} else if !absent(err) {
		return nil, fmt.Errorf("port: PublicKey: %w", err)
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	made, err := client.Ensure(cctx, connect.NewRequest(&keyv1alpha1.EnsureRequest{Purpose: name, Algorithm: purpose.ES384}))
	cancel()
	if err != nil {
		return nil, fmt.Errorf("port: Ensure: %w", err)
	}
	if !made.Msg.GetCreated() {
		return nil, ErrKeyExists
	}
	back, err := publicKey(ctx, client, name)
	if err != nil {
		return nil, fmt.Errorf("port: PublicKey: %w", err)
	}
	if len(made.Msg.GetSpkiDer()) == 0 || !bytes.Equal(back, made.Msg.GetSpkiDer()) {
		return nil, fmt.Errorf("%w: the public key does not read back as the key that was made", ErrBirth)
	}
	k, err := NewKey(ctx, client, name)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(k.pub)
	if err != nil || !bytes.Equal(der, back) {
		_ = k.Close()
		return nil, fmt.Errorf("%w: the key of the signer is not the key that was made", ErrBirth)
	}
	digest := sha512.Sum384([]byte(selfTest))
	sig, err := k.Sign(nil, digest[:], crypto.SHA384)
	if err != nil {
		_ = k.Close()
		return nil, fmt.Errorf("%w: the self-test could not sign: %w", ErrBirth, err)
	}
	// Deliberate: the Signer has verified this signature already; this is a second check with the public key
	// that was read back, and it does not depend on the Signer's own.
	if !ecdsa.VerifyASN1(k.pub, digest[:], sig) {
		_ = k.Close()
		return nil, fmt.Errorf("%w: the signature of the self-test does not verify", ErrBirth)
	}
	return k, nil
}

// publicKey asks for the public key of a purpose and returns its SubjectPublicKeyInfo.
func publicKey(ctx context.Context, client Client, name string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	res, err := client.PublicKey(cctx, connect.NewRequest(&keyv1alpha1.PublicKeyRequest{Purpose: name}))
	if err != nil {
		return nil, err
	}
	return res.Msg.GetSpkiDer(), nil
}

// absent reports whether a refusal of the port says that the purpose has no key.
func absent(err error) bool {
	reason, ok := refusal.Reason(err)
	return ok && reason == "absent" && connect.CodeOf(err) == connect.CodeNotFound
}
