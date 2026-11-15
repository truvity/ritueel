//go:build linux || darwin

package ceremony_test

import (
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
)

// A signature that was made is held to the key that was born for its subject: its key is the pin of
// that key, for the certificate and the removal authorisation of a label and for the list (whose
// subject is the label of the key that signs it).

func TestEveryMadeSignatureIsHeldToThePinOfTheKeyBornForItsSubject(t *testing.T) {
	p, born, made := mkPlanAndKeys(t)
	pinOf := map[string]string{}
	for _, b := range born {
		pinOf[b.Label] = b.Pin
	}
	for i, s := range p.Signatures {
		other := "A"
		if s.Subject == "A" {
			other = "B"
		}
		for name, key := range map[string]string{
			"the pin of the other key":            pinOf[other],
			"a pin that no key has":               strings.Repeat("e", 64),
			"the pin with its last digit changed": pinOf[s.Subject][:63] + "0",
		} {
			if key == pinOf[s.Subject] {
				continue
			}
			t.Run(s.Kind+" "+s.Subject+" "+name+" "+string(rune('1'+i)), func(t *testing.T) {
				m := slices.Clone(made)
				m[i].Key = key
				err := ceremony.CheckPlanAgainstKeys(p, born, m)
				mkWantArtifactError(t, err, "plan against the keys", "signatures")
				if !strings.Contains(err.Error(), "signature "+string(rune('1'+i))) {
					t.Errorf("the error does not name the signature: %v", err)
				}
			})
		}
	}
}

func TestTheListIsHeldToTheKeyOfItsSignerAndNotToTheOtherKey(t *testing.T) {
	p, born, made := mkPlanAndKeys(t)
	last := len(p.Signatures) - 1
	if p.Signatures[last].Kind != "root-list" || p.Signatures[last].Subject != "A" {
		t.Fatalf("the last signature of the plan is %+v", p.Signatures[last])
	}
	if err := ceremony.CheckPlanAgainstKeys(p, born, made); err != nil {
		t.Fatalf("control: %v", err)
	}
	made[last].Key = born[1].Pin
	mkWantArtifactError(t, ceremony.CheckPlanAgainstKeys(p, born, made), "plan against the keys", "signatures")
}

func TestASignatureForASubjectThatNoKeyWasBornForIsRefused(t *testing.T) {
	p, born, made := mkPlanAndKeys(t)
	q := *p
	q.Signatures = slices.Clone(p.Signatures)
	q.Signatures[0].Subject = "C"
	m := slices.Clone(made)
	m[0].Subject = "C"
	mkWantArtifactError(t, ceremony.CheckPlanAgainstKeys(&q, born, m), "plan against the keys", "signatures")
}

func TestAPinThatTwoKeysShareDoesNotLetAKeySignForTheOther(t *testing.T) {
	// Both keys of the list claim the same pin: the signature of B by a key with A's pin is refused,
	// since the pin of B is the one that its birth says.
	p, born, made := mkPlanAndKeys(t)
	m := slices.Clone(made)
	for i, s := range p.Signatures {
		if s.Subject == "B" {
			m[i].Key = born[0].Pin
		}
	}
	mkWantArtifactError(t, ceremony.CheckPlanAgainstKeys(p, born, m), "plan against the keys", "signatures")
}
