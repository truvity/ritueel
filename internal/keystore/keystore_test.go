package keystore_test

import (
	"crypto"
	"io"
	"testing"

	"ritueel.id/ritueel/internal/keystore"
)

// fake is the smallest thing that is a Key: it shows what the interface asks for and nothing more.
type fake struct{}

func (fake) Public() crypto.PublicKey                                  { return nil }
func (fake) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, nil }
func (fake) Kind() keystore.Kind                                       { return keystore.KindSoftware }
func (fake) Copyable() bool                                            { return true }
func (fake) Warnings() []string                                        { return []string{keystore.WarningSoftwareCopyable} }
func (fake) Close() error                                              { return nil }

var _ keystore.Key = fake{}
var _ crypto.Signer = keystore.Key(fake{})

func TestTheKindOfASoftwareKeyIsTheWordOfRootJSON(t *testing.T) {
	if keystore.KindSoftware != "software" {
		t.Errorf("KindSoftware is %q", keystore.KindSoftware)
	}
	if keystore.Kind("software") != keystore.KindSoftware {
		t.Error("the kind is not the plain word")
	}
}

func TestTheWarningOfACopyableKeyIsTheCodeOfTheCeremonyRecord(t *testing.T) {
	if keystore.WarningSoftwareCopyable != "software-copyable" {
		t.Errorf("the code is %q", keystore.WarningSoftwareCopyable)
	}
}

func TestAKeyAnswersTheKindTheCopyAndTheWarningsThroughTheInterface(t *testing.T) {
	var k keystore.Key = fake{}
	if k.Kind() != keystore.KindSoftware || !k.Copyable() || len(k.Warnings()) != 1 || k.Close() != nil {
		t.Error("the interface is not what the fake says")
	}
}
