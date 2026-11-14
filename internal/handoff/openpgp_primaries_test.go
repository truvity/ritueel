package handoff_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// Check 3 for an openpgp-subkey request: after the digest, primaries is exactly the active primaries of the
// root list, in the order of the list ("What the certifier checks", row 3; "The proof file", `primaries`).

func TestTheDigestIsCheckedBeforeThePrimaries(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	f.digest = digestHex([]byte("another request"))
	f.listed = fingerprints(2)
	v, err := f.checker(nil).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeRequestMismatch, 3)
	if got := statuses(v); got != "ppfnnnnnn" {
		t.Errorf("statuses %s", got)
	}
}

func TestPrimariesThatAreNotExactlyTheActivePrimariesOfTheListAreUnknownPrimary(t *testing.T) {
	f := newPGPFixture(t, 3, handoff.StoreSoftware)
	fp := f.fingerprints()
	stranger := newPGPKey(t, pgpPrimaryCreated).fingerprint()
	oneDigit := []byte(fp[1])
	oneDigit[39] = '0'
	if fp[1][39] == '0' {
		oneDigit[39] = '1'
	}
	cases := map[string][]string{
		"a primary that the certifier does not hold":     {fp[0], fp[1], stranger},
		"a primary that the list leaves out":             {fp[0], fp[1]},
		"only the first primary":                         {fp[0]},
		"an extra primary":                               {fp[0], fp[1], fp[2], stranger},
		"the same set in another order":                  {fp[2], fp[0], fp[1]},
		"the first two swapped":                          {fp[1], fp[0], fp[2]},
		"the last two swapped":                           {fp[0], fp[2], fp[1]},
		"the order reversed":                             {fp[2], fp[1], fp[0]},
		"one fingerprint that differs in its last digit": {fp[0], string(oneDigit), fp[2]},
		"the list of another bundle":                     fingerprints(3),
		"a single stranger":                              {stranger},
	}
	for name, list := range cases {
		t.Run(name, func(t *testing.T) {
			g := newPGPFixture(t, 3, handoff.StoreSoftware)
			g.primaries, g.sub, g.subPacket, g.sigs = f.primaries, f.sub, f.subPacket, f.sigs
			g.listed = list
			v, err := g.checker(nil).Check(t.Context(), g.request())
			wantRefusal(t, v, err, handoff.CodeUnknownPrimary, 3)
			if got := statuses(v); got != "ppfnnnnnn" {
				t.Errorf("statuses %s, want ppfnnnnnn", got)
			}
			// The detail says what differs in numbers and holds no byte of the request.
			for _, one := range list {
				if strings.Contains(v.Detail, one) {
					t.Errorf("the detail holds the fingerprint %s: %q", one, v.Detail)
				}
			}
			if v.Detail == "" || !plain(v.Detail) {
				t.Errorf("detail %q", v.Detail)
			}
		})
	}
	// The control: the list as it is.
	f.mustAccept(f.checker(nil))
}

func TestTheOrderOfPrimariesIsTheOrderOfTheListOfTheChecker(t *testing.T) {
	f := newPGPFixture(t, 3, handoff.StoreSoftware)
	// A checker whose list is in the order 3, 1, 2 accepts a request that lists them so, with its
	// back-signatures in that order, and refuses the request in the order 1, 2, 3.
	order := []int{2, 0, 1}
	reordered := func(c *handoff.Config) {
		c.Primaries = nil
		for _, i := range order {
			c.Primaries = append(c.Primaries, f.primaries[i].ref())
		}
	}
	g := newPGPFixture(t, 3, handoff.StoreSoftware)
	g.sub, g.subPacket = f.sub, f.subPacket
	g.primaries = nil
	g.sigs = nil
	for _, i := range order {
		g.primaries = append(g.primaries, f.primaries[i])
		g.sigs = append(g.sigs, g.backSig(f.primaries[i], nil))
	}
	v, err := g.checker(reordered).Check(t.Context(), g.request())
	wantAccepted(t, v, err)
	v, err = f.checker(reordered).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeUnknownPrimary, 3)
	// Another order of the proof with the back-signatures of the checker's order: the listed order is the
	// one that is refused, at check 3, before any signature is read.
	h := newPGPFixture(t, 3, handoff.StoreSoftware)
	h.sub, h.subPacket, h.primaries, h.sigs = g.sub, g.subPacket, g.primaries, g.sigs
	h.listed = []string{g.primaries[1].fingerprint(), g.primaries[0].fingerprint(), g.primaries[2].fingerprint()}
	v, err = h.checker(reordered).Check(t.Context(), h.request())
	wantRefusal(t, v, err, handoff.CodeUnknownPrimary, 3)
}

func TestAPrimaryIsHeldToItsFingerprintAtEveryPosition(t *testing.T) {
	// The position that differs can be any of the sixteen: the first, a middle one and the last.
	f := newPGPFixture(t, handoff.MaxPrimaries, handoff.StoreSoftware)
	for _, at := range []int{0, 7, handoff.MaxPrimaries - 1} {
		g := newPGPFixture(t, 2, handoff.StoreSoftware)
		g.primaries, g.sub, g.subPacket, g.sigs = f.primaries, f.sub, f.subPacket, f.sigs
		list := append([]string(nil), f.fingerprints()...)
		list[at] = newPGPKey(t, pgpPrimaryCreated).fingerprint()
		g.listed = list
		v, err := g.checker(nil).Check(t.Context(), g.request())
		wantRefusal(t, v, err, handoff.CodeUnknownPrimary, 3)
		if !strings.Contains(v.Detail, fmt.Sprint(at+1)) {
			t.Errorf("a difference at position %d: the detail is %q", at+1, v.Detail)
		}
	}
}

// New: the primaries and the capability belong to the delegation.

func TestNewRefusesPrimariesAndACapabilityThatAreNotAsTheConfigurationSays(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	key := newPGPKey(t, pgpPrimaryCreated)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fp := key.fingerprint()
	good := f.refs()
	with := func(change func(c *handoff.Config)) handoff.Config { return f.config(change) }
	otherTime := newPGPKey(t, pgpPrimaryCreated)
	otherTime.priv = key.priv
	otherTime.created = pgpPrimaryCreated.Add(time.Second)
	seventeen := func() []handoff.PrimaryRef {
		var out []handoff.PrimaryRef
		for range handoff.MaxPrimaries + 1 {
			out = append(out, newPGPKey(t, pgpPrimaryCreated).ref())
		}
		return out
	}()
	cases := map[string]handoff.Config{
		"no primaries for an openpgp delegation": with(func(c *handoff.Config) { c.Primaries = nil }),
		"an empty list of primaries":             with(func(c *handoff.Config) { c.Primaries = []handoff.PrimaryRef{} }),
		"17 primaries":                           with(func(c *handoff.Config) { c.Primaries = seventeen }),
		"primaries for an X.509 delegation":      with(func(c *handoff.Config) { c.Delegation = defaultDelegation() }),
		"primaries for an SSH delegation": with(func(c *handoff.Config) {
			c.Delegation = &handoff.Delegation{Name: "n", Type: handoff.TypeSSH, Root: "r"}
		}),
		"a nil key": with(func(c *handoff.Config) { c.Primaries = []handoff.PrimaryRef{{Fingerprint: fp, Created: key.created}} }),
		"a key on P-256": with(func(c *handoff.Config) {
			c.Primaries = []handoff.PrimaryRef{{Fingerprint: fp, Key: &p256.PublicKey, Created: key.created}}
		}),
		"a creation time with a fraction": with(func(c *handoff.Config) {
			c.Primaries = []handoff.PrimaryRef{{Fingerprint: fp, Key: key.pub(), Created: key.created.Add(time.Millisecond)}}
		}),
		"a creation time before 1970": with(func(c *handoff.Config) {
			c.Primaries = []handoff.PrimaryRef{{Fingerprint: fp, Key: key.pub(), Created: time.Unix(-1, 0)}}
		}),
		"a creation time after 2106": with(func(c *handoff.Config) {
			c.Primaries = []handoff.PrimaryRef{{Fingerprint: fp, Key: key.pub(), Created: time.Unix(1<<32, 0)}}
		}),
		"a zero creation time": with(func(c *handoff.Config) { c.Primaries = []handoff.PrimaryRef{{Fingerprint: fp, Key: key.pub()}} }),
		"a fingerprint in upper case": with(func(c *handoff.Config) {
			c.Primaries = []handoff.PrimaryRef{{Fingerprint: strings.ToUpper(fp), Key: key.pub(), Created: key.created}}
		}),
		"a fingerprint of 39 digits": with(func(c *handoff.Config) {
			c.Primaries = []handoff.PrimaryRef{{Fingerprint: fp[1:], Key: key.pub(), Created: key.created}}
		}),
		"a fingerprint of 41 digits": with(func(c *handoff.Config) {
			c.Primaries = []handoff.PrimaryRef{{Fingerprint: fp + "0", Key: key.pub(), Created: key.created}}
		}),
		"an empty fingerprint": with(func(c *handoff.Config) { c.Primaries = []handoff.PrimaryRef{{Key: key.pub(), Created: key.created}} }),
		"a fingerprint of another key": with(func(c *handoff.Config) {
			c.Primaries = []handoff.PrimaryRef{{Fingerprint: good[0].Fingerprint, Key: key.pub(), Created: key.created}}
		}),
		"a fingerprint of another creation time": with(func(c *handoff.Config) {
			c.Primaries = []handoff.PrimaryRef{{Fingerprint: fp, Key: key.pub(), Created: otherTime.created}}
		}),
		"a fingerprint that is not hex": with(func(c *handoff.Config) {
			c.Primaries = []handoff.PrimaryRef{{Fingerprint: strings.Repeat("zz", 20), Key: key.pub(), Created: key.created}}
		}),
		"a fingerprint twice":                     with(func(c *handoff.Config) { c.Primaries = []handoff.PrimaryRef{good[0], good[1], good[0]} }),
		"one fingerprint at the two ends":         with(func(c *handoff.Config) { c.Primaries = []handoff.PrimaryRef{good[0], good[0]} }),
		"one point with two creation times":       with(func(c *handoff.Config) { c.Primaries = []handoff.PrimaryRef{key.ref(), otherTime.ref()} }),
		"a capability of encrypt":                 with(func(c *handoff.Config) { c.Delegation.Capability = "encrypt" }),
		"a capability in upper case":              with(func(c *handoff.Config) { c.Delegation.Capability = "Sign" }),
		"no capability for an openpgp delegation": with(func(c *handoff.Config) { c.Delegation.Capability = "" }),
		"two capabilities in one word":            with(func(c *handoff.Config) { c.Delegation.Capability = "sign,authenticate" }),
		"a capability for an X.509 delegation": with(func(c *handoff.Config) {
			c.Delegation = defaultDelegation()
			c.Delegation.Capability = "sign"
			c.Primaries = nil
		}),
		"a capability for an SSH delegation": with(func(c *handoff.Config) {
			c.Delegation = &handoff.Delegation{Name: "n", Type: handoff.TypeSSH, Root: "r", Capability: "sign"}
			c.Primaries = nil
		}),
		"primaries that hold a bad one with no delegation": with(func(c *handoff.Config) {
			c.Delegation = nil
			c.Primaries = []handoff.PrimaryRef{good[0], {Fingerprint: "00", Key: key.pub(), Created: key.created}}
		}),
		"17 primaries with no delegation": with(func(c *handoff.Config) { c.Delegation = nil; c.Primaries = seventeen }),
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) { wantConfigError(t, cfg) })
	}
	// And what is allowed: primaries with no delegation, none with no delegation, and one to sixteen.
	for name, change := range map[string]func(c *handoff.Config){
		"primaries with no delegation":   func(c *handoff.Config) { c.Delegation = nil },
		"no delegation and no primaries": func(c *handoff.Config) { c.Delegation = nil; c.Primaries = nil },
		"an authenticate capability":     func(c *handoff.Config) { c.Delegation.Capability = "authenticate" },
		"one primary":                    func(c *handoff.Config) { c.Primaries = good[:1] },
		"an X.509 delegation, no primaries": func(c *handoff.Config) {
			c.Delegation = defaultDelegation()
			c.Primaries = nil
		},
	} {
		if _, err := handoff.New(with(change)); err != nil {
			t.Errorf("%s: New refused it: %v", name, err)
		}
	}
	sixteen := newPGPFixture(t, handoff.MaxPrimaries, handoff.StoreSoftware)
	if _, err := handoff.New(sixteen.config(nil)); err != nil {
		t.Errorf("sixteen primaries: %v", err)
	}
}

func TestTheCheckerKeepsItsOwnCopyOfThePrimaries(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	cfg := f.config(nil)
	chk := mustNew(t, cfg)
	req := f.request()
	v, err := chk.Check(t.Context(), req)
	wantAccepted(t, v, err)
	// Change the list, an entry, the key and the capability of the delegation after New.
	cfg.Primaries[0].Fingerprint = strings.Repeat("0", 40)
	cfg.Primaries[1] = cfg.Primaries[0]
	cfg.Primaries[0].Created = time.Unix(1, 0)
	//nolint:staticcheck // the coordinates are the only way to change a key that the caller still holds
	cfg.Primaries[0].Key.X.SetInt64(1)
	//nolint:staticcheck // see above
	cfg.Primaries[0].Key.Y.SetInt64(1)
	cfg.Delegation.Capability = "authenticate"
	cfg.Primaries = nil
	v, err = chk.Check(t.Context(), req)
	wantAccepted(t, v, err)
}
