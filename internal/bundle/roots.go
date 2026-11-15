package bundle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/rootlist"
)

// The files of a trust set that Roots reads (docs/reference/root-list.md, "Files").
const (
	rootListFile = "root-list.json"
	caBundleFile = "ca-bundle.pem"
)

// TrustSet names a trust set: its folder name and its number.
type TrustSet struct {
	// Name is the name of the folder, <number>-<eight hex digits>.
	Name string
	// Number is the trust sequence in the name, at least 1.
	Number int64
}

// setName is the spelling of the name of a trust set: the number in plain decimal digits with no leading zero,
// a hyphen, and eight lower-case hexadecimal digits. The spelling is proposed on docs/reference/bundle.md
// ("How a name carries its identity"); this is the one place in this package that holds it.
var setName = regexp.MustCompile(`^([1-9][0-9]*)-([0-9a-f]{8})$`)

// parseSetName reads the name of a trust set. A name of another form, or a number that does not fit an int64,
// is not a set name.
func parseSetName(name string) (TrustSet, bool) {
	m := setName.FindStringSubmatch(name)
	if m == nil {
		return TrustSet{}, false
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return TrustSet{}, false
	}
	return TrustSet{Name: name, Number: n}, true
}

// Roots returns the root keys of the bundle in the form the checks need: the subject and the key of each,
// read from the newest trust set (record 0006, rule 12), and the set they were read from.
//
// The newest set is the one with the largest number, compared as a number. A name that is not a trust set
// is ignored, and so is a leftover temporary name; two sets with one number are an error; no set is an error
// that wraps [ErrNoTrustSet]. The newest set is never replaced by an older one: when its files are bad the
// error says so, and no older set is read. The list is read by the strict reader of package rootlist, its
// sequence must be the number of the folder, and the CA bundle must be the bundle of that list, as
// [rootlist.VerifyCABundle] checks it. Each certificate must hold an ECDSA key on P-384.
//
// The signature of the list (root-list.jws) and the date of its expiry are not checked here: verify
// root-list and check history do that, and an expired list must not stop a person from reading a request.
// Roots reads no keyring file; [Bundle.Primaries] does, from the same set.
func (b *Bundle) Roots() ([]handoff.RootRef, TrustSet, error) {
	n, err := b.readNewest()
	if err != nil {
		return nil, TrustSet{}, err
	}
	return n.roots, n.set, nil
}

// newestSet is what one reading of the newest trust set gives: its name and number, its root list as the
// strict reader made it, and its roots in the order of the list. [Bundle.Roots], [Bundle.Primaries] and
// [Bundle.Checker] all take their data from one of these, so that the roots and the primaries of one run are
// read from the same set.
type newestSet struct {
	set   TrustSet
	list  *rootlist.List
	roots []handoff.RootRef
}

// readNewest finds the newest trust set and reads its list and its CA bundle, once. It is the one place that
// picks the newest set (see [Bundle.Roots] for the rules) and the one place that reads the files that every
// trust set has. It reads no keyring file.
func (b *Bundle) readNewest() (*newestSet, error) {
	if err := b.usable(); err != nil {
		return nil, err
	}
	ents, err := fsx.ReadDir(b.fsys, TrustDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %w", ErrNoTrustSet, err)
		}
		return nil, fmt.Errorf("bundle: the folder trust cannot be read: %w", err)
	}
	var newest TrustSet
	byNumber := map[int64]string{}
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(strings.ToLower(name), fsx.TempPrefix) {
			continue
		}
		set, ok := parseSetName(name)
		if !ok {
			continue
		}
		if other, dup := byNumber[set.Number]; dup {
			return nil, fmt.Errorf("bundle: two trust sets have the number %d: %s and %s", set.Number, other, set.Name)
		}
		byNumber[set.Number] = set.Name
		if set.Number > newest.Number {
			newest = set
		}
	}
	if newest.Number == 0 {
		return nil, ErrNoTrustSet
	}
	list, refs, err := b.readSet(newest)
	if err != nil {
		return nil, err
	}
	return &newestSet{set: newest, list: list, roots: refs}, nil
}

// readSet reads the list and the CA bundle of one trust set and returns the list and its roots in the order of
// the list.
func (b *Bundle) readSet(set TrustSet) (*rootlist.List, []handoff.RootRef, error) {
	at := TrustDir + "/" + set.Name + "/"
	listData, err := fsx.ReadFile(b.fsys, at+rootListFile)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle: the newest trust set %s: %w", set.Name, err)
	}
	pemData, err := fsx.ReadFile(b.fsys, at+caBundleFile)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle: the newest trust set %s: %w", set.Name, err)
	}
	list, err := rootlist.ParseList(listData)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle: the newest trust set %s: %s: %w", set.Name, rootListFile, err)
	}
	if list.Sequence != set.Number {
		return nil, nil, fmt.Errorf("bundle: the newest trust set %s: the sequence of %s is %d, and the number of the folder is %d", set.Name, rootListFile, list.Sequence, set.Number)
	}
	if v := rootlist.VerifyCABundle(pemData, list); !v.Accepted {
		return nil, nil, fmt.Errorf("bundle: the newest trust set %s: %s is not the bundle of the list: %s", set.Name, caBundleFile, v.Detail)
	}
	// The bundle has the form that VerifyCABundle accepted: a first line, and one certificate for each root of
	// the list, in the order of the list. The certificates are read once more here only for their keys.
	refs := make([]handoff.RootRef, 0, len(list.Roots))
	rest := pemData
	for i := range list.Roots {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			return nil, nil, fmt.Errorf("bundle: the newest trust set %s: certificate %d of %s is missing", set.Name, i+1, caBundleFile)
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("bundle: the newest trust set %s: certificate %d of %s does not parse", set.Name, i+1, caBundleFile)
		}
		key, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || key == nil || key.Curve != elliptic.P384() {
			return nil, nil, fmt.Errorf("bundle: the newest trust set %s: the key of certificate %d is not an ECDSA key on P-384", set.Name, i+1)
		}
		refs = append(refs, handoff.RootRef{Subject: bytes.Clone(cert.RawSubject), Key: key})
	}
	return list, refs, nil
}
