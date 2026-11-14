package pki_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// The request as bytes: ParseRequest reads the bytes that were signed, once, and IntermediateTBS issues
// what that reading shows. The cases are those of the form of a request (RFC 2986, RFC 2985, the contract).

var (
	oidChallengePassword = mustOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7})
	oidExtensionRequest  = mustOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14})
)

func algDER(last byte) []byte {
	return []byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, last}
}

func goodRequest(t testing.TB) *testCSR { return withExtensions(t, goodExtensions()...) }

func TestParseRequestAcceptsTheGoodRequest(t *testing.T) {
	csr := goodRequest(t)
	der := csr.DER()
	r, err := pki.ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.DER(), der) || !bytes.Equal(r.Subject(), csr.RawSubject) {
		t.Error("the view does not hold the request and its subject")
	}
	if !r.PublicKey().Equal(&csr.Key.PublicKey) {
		t.Error("the key of the view is not the key of the request")
	}
	exts := r.Extensions()
	if len(exts) != len(csr.Extensions) {
		t.Fatalf("%d extensions, want %d", len(exts), len(csr.Extensions))
	}
	for i, e := range exts {
		w := csr.Extensions[i]
		if !e.Id.Equal(w.Id) || e.Critical != w.Critical || !bytes.Equal(e.Value, w.Value) {
			t.Errorf("extension %d is %+v, want %+v", i, e, w)
		}
	}
	// A high s is a signature that verifies, and is read.
	hs := goodRequest(t)
	hs.SignatureEdit = func(sig []byte) []byte { return highS(t, sig) }
	if _, err := pki.ParseRequest(hs.DER()); err != nil {
		t.Errorf("a signature with a high s is refused: %v", err)
	}
}

// What the request's own form refuses: each row is ErrRequest, the text has the words of the rule.
func TestParseRequestRefusesWhatTheFormOfARequestDoesNot(t *testing.T) {
	sha1Alg := []byte{0x30, 0x09, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01}
	attr := func(oid []byte, values ...[]byte) []byte { return tlv(0x30, oid, tlv(0x31, values...)) }
	goodExts := func() []byte { return extensionsValue(goodExtensions()) }
	ext := func(parts ...[]byte) []byte { return tlv(0x30, parts...) }
	kuOID := mustOIDOf(oidKeyUsage)
	kuValue := tlv(0x04, bitString(kuKeyCertSign))
	bcExt := func() []byte {
		return ext(mustOIDOf(oidBasicConstraints), []byte{0x01, 0x01, 0xff}, tlv(0x04, []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00}))
	}
	kuExt := func() []byte { return ext(kuOID, []byte{0x01, 0x01, 0xff}, kuValue) }
	list := func(exts ...[]byte) []byte { return tlv(0x30, exts...) }

	type row struct {
		name string
		edit func(c *testCSR)
		say  string
	}
	rows := []row{
		// The version.
		{"version 1", func(c *testCSR) { c.Version = []byte{0x02, 0x01, 0x01} }, "version"},
		{"version 7", func(c *testCSR) { c.Version = []byte{0x02, 0x01, 0x07} }, "version"},
		{"version -1", func(c *testCSR) { c.Version = []byte{0x02, 0x01, 0xff} }, "version"},
		{"a version that is not minimal", func(c *testCSR) { c.Version = []byte{0x02, 0x02, 0x00, 0x00} }, "version"},
		{"a version that is an enumerated", func(c *testCSR) { c.Version = []byte{0x0a, 0x01, 0x00} }, "version"},
		{"no version, the subject first", func(c *testCSR) { c.Version = []byte{} }, "request info"},
		// The algorithm.
		{"ecdsa-with-SHA1", func(c *testCSR) { c.Algorithm, c.Digest = sha1Alg, crypto.SHA1 }, "ecdsa-with-SHA384"},
		{"ecdsa-with-SHA256", func(c *testCSR) { c.Algorithm, c.Digest = algDER(0x02), crypto.SHA256 }, "ecdsa-with-SHA384"},
		{"ecdsa-with-SHA512", func(c *testCSR) { c.Algorithm, c.Digest = algDER(0x04), crypto.SHA512 }, "ecdsa-with-SHA384"},
		{"ecdsa-with-SHA384 with parameters", func(c *testCSR) {
			c.Algorithm = []byte{0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x05, 0x00}
		}, "ecdsa-with-SHA384"},
		{"SHA-384 named and SHA-256 signed", func(c *testCSR) { c.Digest = crypto.SHA256 }, "does not verify"},
		// The signature.
		{"a signature with unused bits", func(c *testCSR) { c.UnusedBits = 1 }, "bit string"},
		{"a signature that is raw r and s", func(c *testCSR) { c.SignatureEdit = func([]byte) []byte { return bytes.Repeat([]byte{7}, 96) } }, "DER ECDSA"},
		{"a signature with a byte after it", func(c *testCSR) { c.SignatureEdit = func(s []byte) []byte { return append(s, 0) } }, "DER ECDSA"},
		{"a signature changed in its last byte", func(c *testCSR) { c.SignatureEdit = func(s []byte) []byte { s[len(s)-1] ^= 1; return s } }, "does not verify"},
		{"a signature by another key", func(c *testCSR) { c.Key = newKey(t); c.RawSubjectPublicKeyInfo = goodRequest(t).SPKI() }, "does not verify"},
		// What is after.
		{"an element after the info", func(c *testCSR) { c.OuterTrailer = []byte{0x05, 0x00} }, "after its signature"},
		{"bytes after the request", func(c *testCSR) { c.AfterRequest = []byte{0x00} }, "nothing after it"},
		{"a second request after the first", func(c *testCSR) { c.AfterRequest = goodRequest(t).DER() }, "nothing after it"},
		{"an element after the attributes in the info", func(c *testCSR) { c.InfoTrailer = []byte{0x05, 0x00} }, "after its attributes"},
		// The attributes.
		{"no attribute", func(c *testCSR) { c.Attributes = [][]byte{} }, "no attribute"},
		{"two extension requests", func(c *testCSR) {
			c.Attributes = [][]byte{attr(oidExtensionRequest, list(bcExt(), kuExt())), attr(oidExtensionRequest, list(ext(mustOIDOf(oidNameConstraints), []byte{0x01, 0x01, 0xff}, tlv(0x04, nameConstraintsValue(2, "example.org")))))}
		}, "more than one attribute"},
		{"an empty set and then a good extension request", func(c *testCSR) {
			c.Attributes = [][]byte{attr(oidExtensionRequest), attr(oidExtensionRequest, goodExts())}
		}, "more than one attribute"},
		{"an extension request with an empty set", func(c *testCSR) { c.Attributes = [][]byte{attr(oidExtensionRequest)} }, "extension request"},
		{"one set with two values", func(c *testCSR) {
			c.Attributes = [][]byte{attr(oidExtensionRequest, list(bcExt(), kuExt()), list(ext(mustOIDOf(oidNameConstraints), []byte{0x01, 0x01, 0xff}, tlv(0x04, nameConstraintsValue(2, "example.org")))))}
		}, "more than one value"},
		{"a challenge password beside the good attribute", func(c *testCSR) {
			c.Attributes = [][]byte{attr(oidExtensionRequest, goodExts()), attr(oidChallengePassword, tlv(0x13, []byte("secret")))}
		}, "more than one attribute"},
		{"a challenge password and nothing else", func(c *testCSR) {
			c.Attributes = [][]byte{attr(oidChallengePassword, tlv(0x13, []byte("secret")))}
		}, "not the extension request"},
		{"an attribute that is not a sequence", func(c *testCSR) { c.Attributes = [][]byte{tlv(0x31, oidExtensionRequest)} }, "no attribute"},
		{"an extension request whose set is a sequence", func(c *testCSR) {
			c.Attributes = [][]byte{tlv(0x30, oidExtensionRequest, tlv(0x30, goodExts()))}
		}, "one set"},
		{"an extension request with a value that is not the extensions", func(c *testCSR) {
			c.Attributes = [][]byte{attr(oidExtensionRequest, tlv(0x04, []byte("x")))}
		}, "no value that is the extensions"},
		{"an extension request with a byte after its set", func(c *testCSR) {
			c.Attributes = [][]byte{tlv(0x30, oidExtensionRequest, tlv(0x31, goodExts()), []byte{0x05, 0x00})}
		}, "one set with nothing after"},
		{"empty extensions", func(c *testCSR) { c.ExtensionsDER = tlv(0x30) }, "empty sequence"},
		// The tags of the elements.
		{"an info that is a set", func(c *testCSR) { c.InfoTag = 0x31 }, "request info is not a sequence"},
		{"an info that is an octet string", func(c *testCSR) { c.InfoTag = 0x04 }, "request info is not a sequence"},
		{"an info that is a primitive sequence", func(c *testCSR) { c.InfoTag = 0x10 }, "request info is not a sequence"},
		{"an info of the context class", func(c *testCSR) { c.InfoTag = 0xb0 }, "request info is not a sequence"},
		{"an info of the application class", func(c *testCSR) { c.InfoTag = 0x70 }, "request info is not a sequence"},
		{"a subject that is a set", func(c *testCSR) { c.RawSubject = tlv(0x31, c.RawSubject[2:]) }, "subject of the request is not a sequence"},
		{"a subject that is an octet string", func(c *testCSR) { c.RawSubject = tlv(0x04, c.RawSubject[2:]) }, "subject of the request is not a sequence"},
		{"a subject that is a primitive sequence", func(c *testCSR) { c.RawSubject = tlv(0x10, c.RawSubject[2:]) }, "subject of the request is not a sequence"},
		{"a subject of the context class", func(c *testCSR) { c.RawSubject = tlv(0xb0, c.RawSubject[2:]) }, "subject of the request is not a sequence"},
		{"attributes of tag [1]", func(c *testCSR) { c.AttributesTag = 0xa1 }, "not [0] in the constructed form"},
		{"attributes of tag [0] primitive", func(c *testCSR) { c.AttributesTag = 0x80 }, "not [0] in the constructed form"},
		{"attributes that are a universal set", func(c *testCSR) { c.AttributesTag = 0x31 }, "not [0] in the constructed form"},
		{"attributes that are a universal sequence", func(c *testCSR) { c.AttributesTag = 0x30 }, "not [0] in the constructed form"},
		{"attributes of the application class", func(c *testCSR) { c.AttributesTag = 0x60 }, "not [0] in the constructed form"},
		{"a signature that is an octet string", func(c *testCSR) {
			c.SignatureElement = func(b []byte) []byte { b[0] = 0x04; return b }
		}, "bit string"},
		{"a signature that is a constructed bit string", func(c *testCSR) {
			c.SignatureElement = func(b []byte) []byte { b[0] = 0x23; return b }
		}, "bit string"},
		{"a signature of the context class", func(c *testCSR) {
			c.SignatureElement = func(b []byte) []byte { b[0] = 0x83; return b }
		}, "bit string"},
		{"a signature that is an empty bit string", func(c *testCSR) {
			c.SignatureElement = func([]byte) []byte { return []byte{0x03, 0x00} }
		}, "bit string"},
		{"a signature that is only the unused-bits octet", func(c *testCSR) {
			c.SignatureElement = func([]byte) []byte { return []byte{0x03, 0x01, 0x00} }
		}, "DER ECDSA"},
		// An extension.
		{"a critical flag that is stated FALSE", func(c *testCSR) {
			c.ExtensionsDER = list(ext(mustOIDOf(oidBasicConstraints), []byte{0x01, 0x01, 0x00}, tlv(0x04, []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00})), kuExt())
		}, "critical flag"},
		{"a critical flag that is 0x01", func(c *testCSR) {
			c.ExtensionsDER = list(ext(mustOIDOf(oidBasicConstraints), []byte{0x01, 0x01, 0x01}, tlv(0x04, []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00})), kuExt())
		}, "critical flag"},
		{"an extension that is only an object identifier", func(c *testCSR) { c.ExtensionsDER = list(ext(mustOIDOf(oidBasicConstraints)), kuExt()) }, "has no value"},
		{"an extension that is a primitive sequence", func(c *testCSR) { c.ExtensionsDER = list(tlv(0x10, mustOIDOf(oidBasicConstraints), tlv(0x04, nil))) }, "not a DER sequence"},
		{"an extension of the context class", func(c *testCSR) { c.ExtensionsDER = list(tlv(0xb0, mustOIDOf(oidBasicConstraints), tlv(0x04, nil))) }, "not a DER sequence"},
		{"a value that is a constructed octet string", func(c *testCSR) {
			c.ExtensionsDER = list(ext(mustOIDOf(oidBasicConstraints), []byte{0x01, 0x01, 0xff}, tlv(0x24, tlv(0x04, nil))), kuExt())
		}, "octet string"},
		{"a value of the context class", func(c *testCSR) {
			c.ExtensionsDER = list(ext(mustOIDOf(oidBasicConstraints), []byte{0x01, 0x01, 0xff}, tlv(0x84, nil)), kuExt())
		}, "octet string"},
		{"a value that is a UTF8String", func(c *testCSR) {
			c.ExtensionsDER = list(ext(mustOIDOf(oidBasicConstraints), []byte{0x01, 0x01, 0xff}, tlv(0x0c, nil)), kuExt())
		}, "octet string"},
		{"extensions that are a primitive sequence", func(c *testCSR) { c.Attributes = [][]byte{attr(oidExtensionRequest, tlv(0x10, goodExts()[2:]))} }, "no value that is the extensions"},
		{"extensions of the context class", func(c *testCSR) { c.Attributes = [][]byte{attr(oidExtensionRequest, tlv(0xb0, goodExts()[2:]))} }, "no value that is the extensions"},
		{"extensions that are a set", func(c *testCSR) { c.Attributes = [][]byte{attr(oidExtensionRequest, tlv(0x31, goodExts()[2:]))} }, "no value that is the extensions"},
		{"an attribute that is a primitive sequence", func(c *testCSR) { c.Attributes = [][]byte{tlv(0x10, oidExtensionRequest, tlv(0x31, goodExts()))} }, "no attribute"},
		{"an attribute of the context class", func(c *testCSR) { c.Attributes = [][]byte{tlv(0xb0, oidExtensionRequest, tlv(0x31, goodExts()))} }, "no attribute"},
		{"a request of two elements", func(c *testCSR) { c.SignatureElement = func([]byte) []byte { return nil } }, "info, an algorithm and a signature"},
		{"a stray octet after the extensions in their sequence", func(c *testCSR) { c.ExtensionsDER = list(bcExt(), kuExt(), []byte{0x00}) }, "not a DER sequence"},
		{"a fourth element in an extension", func(c *testCSR) {
			c.ExtensionsDER = list(ext(mustOIDOf(oidBasicConstraints), []byte{0x01, 0x01, 0xff}, tlv(0x04, []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00}), []byte{0x05, 0x00}), kuExt())
		}, "after its value"},
		{"an extension with no value", func(c *testCSR) {
			c.ExtensionsDER = list(ext(mustOIDOf(oidBasicConstraints), []byte{0x01, 0x01, 0xff}), kuExt())
		}, "no value"},
		{"an extension whose value is not an octet string", func(c *testCSR) {
			c.ExtensionsDER = list(ext(mustOIDOf(oidBasicConstraints), []byte{0x01, 0x01, 0xff}, []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00}), kuExt())
		}, "octet string"},
		{"an extension that is not a sequence", func(c *testCSR) { c.ExtensionsDER = list(tlv(0x31, mustOIDOf(oidBasicConstraints))) }, "not a DER sequence"},
		{"an extension with no object identifier", func(c *testCSR) { c.ExtensionsDER = list(ext(tlv(0x02, []byte{1}), tlv(0x04, nil))) }, "object identifier"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			csr := goodRequest(t)
			r.edit(csr)
			der := csr.DER()
			v, err := pki.ParseRequest(der)
			refused(t, err, pki.ErrRequest)
			if v != nil {
				t.Error("a request came with the error")
			}
			if err != nil && !strings.Contains(err.Error(), r.say) {
				t.Errorf("the text does not say %q: %q", r.say, err.Error())
			}
			// IntermediateTBS reads the same bytes, so it refuses the same request in the same way.
			root := buildRoot(t, nil)
			p := root.interParams(csr)
			tbs, err2 := intermediateTBS(t, p)
			refused(t, err2, pki.ErrRequest)
			if tbs != nil {
				t.Error("a body came with the error")
			}
		})
	}
	t.Run("the request that every row started from is accepted", func(t *testing.T) {
		if _, err := pki.ParseRequest(goodRequest(t).DER()); err != nil {
			t.Fatal(err)
		}
	})
}

// id-ecPublicKey, the algorithm of every ECDSA key (RFC 5480).
var oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// The key of a request: the bytes must be the canonical encoding of a P-384 key.
func TestParseRequestRefusesTheKeysThatAreNotP384(t *testing.T) {
	good := goodRequest(t)
	spki := good.SPKI()
	// The check: bytes that are not a SubjectPublicKeyInfo are a fault of the form (malformed); a SubjectPublicKeyInfo that is not the key
	// of ECDSA on P-384 is the key check (algorithm-unsupported).
	rows := []struct {
		name  string
		key   []byte
		words string
		check pki.Check
	}{
		{"a key with a byte more", append(append([]byte(nil), spki...), 0), "a version, a subject, a key", pki.CheckMalformed},
		{"a key cut short", spki[:len(spki)-1], "after its attributes", pki.CheckMalformed},
		{"a key with a point changed", append(append([]byte(nil), spki[:len(spki)-1]...), spki[len(spki)-1]^1), "the key of the request", pki.CheckAlgorithm},
		{"an empty key", []byte{0x30, 0x00}, "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a bit string alone", tlv(0x03, []byte{0, 4}), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		// encoding/asn1 reads a structure and ignores an element after its last field, so these are P-384 keys that the standard library
		// reads and that are not a SubjectPublicKeyInfo (an algorithm and a bit string, nothing else): the form refuses them.
		{"a key with an element after its bit string", tlv(0x30, spki[2:], tlv(0x05)), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key with two elements after its bit string", tlv(0x30, spki[2:], tlv(0x05), tlv(0x02, []byte{1})), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key with an element after its algorithm", withElementAfterTheAlgorithm(t, spki), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key whose algorithm has three elements", withAlgorithmOf(t, spki, func(a asn1.RawValue) []byte { return tlv(0x30, a.Bytes, tlv(0x05), tlv(0x05)) }), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		// The algorithm of a key is an AlgorithmIdentifier (an identifier and at most one element of parameters): what is not one is a
		// key that is not a public key structure (malformed); a well-formed algorithm that is not P-384 is check 4.
		{"a key whose algorithm is an empty sequence", withAlgorithmOf(t, spki, func(asn1.RawValue) []byte { return tlv(0x30) }), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key whose algorithm starts with a null", withAlgorithmOf(t, spki, func(asn1.RawValue) []byte { return tlv(0x30, tlv(0x05), tlv(0x05)) }), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key whose algorithm is a null alone", withAlgorithmOf(t, spki, func(asn1.RawValue) []byte { return tlv(0x30, tlv(0x05)) }), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key whose algorithm is an integer alone", withAlgorithmOf(t, spki, func(asn1.RawValue) []byte { return tlv(0x30, tlv(0x02, []byte{1})) }), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key whose algorithm starts with an integer and holds an identifier", withAlgorithmOf(t, spki, func(asn1.RawValue) []byte { return tlv(0x30, tlv(0x02, []byte{1}), mustOIDOf(oidECPublicKey)) }), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key whose algorithm is an octet string alone", withAlgorithmOf(t, spki, func(asn1.RawValue) []byte { return tlv(0x30, tlv(0x04, []byte{1})) }), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key whose algorithm is an identifier and two more elements", withAlgorithmOf(t, spki, func(asn1.RawValue) []byte {
			return tlv(0x30, mustOIDOf(oidECPublicKey), tlv(0x05), tlv(0x05))
		}), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key whose algorithm is an identifier and a null and an integer", withAlgorithmOf(t, spki, func(asn1.RawValue) []byte {
			return tlv(0x30, mustOIDOf(oidECPublicKey), tlv(0x05), tlv(0x02, []byte{1}))
		}), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key whose algorithm is a bare identifier", withAlgorithmOf(t, spki, func(asn1.RawValue) []byte { return mustOIDOf(oidECPublicKey) }), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		// A well-formed algorithm that is not ECDSA on P-384 is the key check, and so is id-ecPublicKey with no parameters.
		{"a key whose algorithm is id-ecPublicKey with no parameters", withAlgorithmOf(t, spki, func(asn1.RawValue) []byte { return tlv(0x30, mustOIDOf(oidECPublicKey)) }), "not ECDSA on P-384", pki.CheckAlgorithm},
		{"a key whose algorithm is id-ecPublicKey with null parameters", withAlgorithmOf(t, spki, func(asn1.RawValue) []byte { return tlv(0x30, mustOIDOf(oidECPublicKey), tlv(0x05)) }), "not ECDSA on P-384", pki.CheckAlgorithm},
		{"a key whose algorithm is an identifier of another algorithm with no parameters", withAlgorithmOf(t, spki, func(asn1.RawValue) []byte { return tlv(0x30, mustOIDOf(asn1.ObjectIdentifier{1, 3, 101, 112})) }), "not ECDSA on P-384", pki.CheckAlgorithm},
		{"a key whose algorithm is an identifier of another algorithm with an integer as parameters", withAlgorithmOf(t, spki, func(asn1.RawValue) []byte {
			return tlv(0x30, mustOIDOf(asn1.ObjectIdentifier{1, 2, 3}), tlv(0x02, []byte{1}))
		}), "not ECDSA on P-384", pki.CheckAlgorithm},
		// The key element itself, and its second element, in another tag or class: not a SubjectPublicKeyInfo, whatever it holds.
		{"a key that is a set", append([]byte{0x31, spki[1]}, spki[2:]...), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key that is a primitive sequence", append([]byte{0x10, spki[1]}, spki[2:]...), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key of the context class", append([]byte{0xb0, spki[1]}, spki[2:]...), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key of the application class", append([]byte{0x70, spki[1]}, spki[2:]...), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key with a constructed bit string", withKeyElement(t, spki, func(asn1.RawValue) []byte { return tlv(0x23, tlv(0x03, []byte{0, 1})) }), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key with a bit string of the context class", withKeyElement(t, spki, func(k asn1.RawValue) []byte { return append([]byte{0x83}, k.FullBytes[1:]...) }), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key with an octet string for its bit string", withKeyElement(t, spki, func(k asn1.RawValue) []byte { return append([]byte{0x04}, k.FullBytes[1:]...) }), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key whose algorithm holds an element that is not DER", withAlgorithmOf(t, spki, func(asn1.RawValue) []byte { return []byte{0x30, 0x03, 0x06, 0x05, 0x01} }), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key whose algorithm is a set", withAlgorithmOf(t, spki, func(a asn1.RawValue) []byte { return tlv(0x31, a.Bytes) }), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key whose algorithm is a primitive sequence", withAlgorithmOf(t, spki, func(a asn1.RawValue) []byte { return tlv(0x10, a.Bytes) }), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key with three elements", tlv(0x30, spki[2:], tlv(0x03, []byte{0, 1}), tlv(0x05)), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"a key with its algorithm alone", withAlgorithmOnly(t, spki), "not a SubjectPublicKeyInfo", pki.CheckMalformed},
		{"an algorithm and a bit string that are not a key", tlv(0x30, tlv(0x30, mustOIDOf(asn1.ObjectIdentifier{1, 2, 3})), tlv(0x03, []byte{0, 4})), "not ECDSA on P-384", pki.CheckAlgorithm},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			c := copyCSR(good)
			c.RawSubjectPublicKeyInfo = r.key
			_, err := pki.ParseRequest(c.DER())
			refusedSaying(t, err, pki.ErrRequest, r.words)
			if got := pki.CheckOf(err); got != r.check {
				t.Errorf("check %q, want %q", got, r.check)
			}
			// RequestKey and RequestKeyFile say the same, with no key, and the builder says the same check.
			key, kerr := pki.RequestKey(c.DER())
			if key != nil || kerr == nil || kerr.Error() != err.Error() || pki.CheckOf(kerr) != r.check {
				t.Errorf("RequestKey: %v, %v (check %q), want no key and the error of ParseRequest", key, kerr, pki.CheckOf(kerr))
			}
			fkey, ferr := pki.RequestKeyFile([]byte(armor(c.DER(), "CERTIFICATE REQUEST", "\n") + "\n"))
			if fkey != nil || ferr == nil || ferr.Error() != err.Error() {
				t.Errorf("RequestKeyFile: %v, %v", fkey, ferr)
			}
			_, terr := pki.IntermediateTBS(buildRoot(t, nil).interParams(c))
			if terr == nil || terr.Error() != err.Error() || pki.CheckOf(terr) != r.check {
				t.Errorf("IntermediateTBS: %v (check %q)", terr, pki.CheckOf(terr))
			}
		})
	}
	for _, c := range []struct {
		name string
		csr  *testCSR
	}{
		{"P-256", &testCSR{Key: p256Key(t), RawSubject: goodSubject(), Extensions: goodExtensions()}},
		{"P-521", &testCSR{Key: p521Key(t), RawSubject: goodSubject(), Extensions: goodExtensions()}},
	} {
		t.Run("a "+c.name+" request signed with SHA-384", func(t *testing.T) {
			_, err := pki.ParseRequest(c.csr.DER())
			refusedSaying(t, err, pki.ErrRequest, "ECDSA on P-384")
			if got := pki.CheckOf(err); got != pki.CheckAlgorithm {
				t.Errorf("check %q, want algorithm-unsupported", got)
			}
		})
	}
}

func TestParseRequestSizeLimit(t *testing.T) {
	if pki.MaxRequestSize != 256*1024 {
		t.Fatalf("MaxRequestSize = %d, want 262144", pki.MaxRequestSize)
	}
	exact := func(size int) []byte { return exactRequest(t, size) }
	limit := exact(pki.MaxRequestSize)
	t.Run("exactly the limit is read", func(t *testing.T) {
		if _, err := pki.ParseRequest(limit); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("one octet less is read", func(t *testing.T) {
		if _, err := pki.ParseRequest(exact(pki.MaxRequestSize - 1)); err != nil {
			t.Fatal(err)
		}
	})
	more := exact(pki.MaxRequestSize + 1)
	t.Run("one octet more is refused", func(t *testing.T) {
		_, err := pki.ParseRequest(more)
		refused(t, err, pki.ErrRequest)
		if err != nil && !strings.Contains(err.Error(), "longer than") {
			t.Errorf("not the size rule: %q", err.Error())
		}
	})
	t.Run("bytes that are no request are refused as too long beyond the limit and as no request at it", func(t *testing.T) {
		_, err := pki.ParseRequest(make([]byte, pki.MaxRequestSize+1))
		refused(t, err, pki.ErrRequest)
		if err != nil && !strings.Contains(err.Error(), "longer than") {
			t.Errorf("not the size rule: %q", err.Error())
		}
		_, err = pki.ParseRequest(make([]byte, pki.MaxRequestSize))
		refused(t, err, pki.ErrRequest)
		if err != nil && strings.Contains(err.Error(), "longer than") {
			t.Errorf("the limit itself is refused as too long: %q", err.Error())
		}
	})
	t.Run("IntermediateTBS refuses the same", func(t *testing.T) {
		root := buildRoot(t, nil)
		p := root.interParams(goodRequest(t))
		p.CSR = more
		_, err := intermediateTBS(t, p)
		refused(t, err, pki.ErrRequest)
		if err != nil && !strings.Contains(err.Error(), "longer than") {
			t.Errorf("not the size rule: %q", err.Error())
		}
		// The request of exactly the limit passes the size rule, and every other rule: it is issued.
		p.CSR = limit
		if _, err := intermediateTBS(t, p); err != nil {
			t.Errorf("the request of exactly the limit is refused: %v", err)
		}
	})
}

// The view cannot be changed by its caller, and it agrees with what is issued.
func TestRequestViewIsReadOnlyAndAgreesWithTheIssuedBody(t *testing.T) {
	csr := goodRequest(t)
	der := csr.DER()
	input := append([]byte(nil), der...)
	v, err := pki.ParseRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	// The caller's slice is changed after the read.
	for i := range input {
		input[i] = 0
	}
	if !bytes.Equal(v.DER(), der) {
		t.Error("the view changed with the caller's slice")
	}
	// What the view returns is a copy.
	d := v.DER()
	for i := range d {
		d[i] ^= 0xff
	}
	s := v.Subject()
	for i := range s {
		s[i] ^= 0xff
	}
	exts := v.Extensions()
	for i := range exts {
		for j := range exts[i].Value {
			exts[i].Value[j] ^= 0xff
		}
		for j := range exts[i].Id {
			exts[i].Id[j] = 99
		}
		exts[i].Critical = !exts[i].Critical
	}
	key := v.PublicKey()
	x, _ := coordinates(key)
	x.SetInt64(7)
	if !bytes.Equal(v.DER(), der) || !bytes.Equal(v.Subject(), csr.RawSubject) {
		t.Error("the view changed with what it returned")
	}
	for i, e := range v.Extensions() {
		w := csr.Extensions[i]
		if !e.Id.Equal(w.Id) || e.Critical != w.Critical || !bytes.Equal(e.Value, w.Value) {
			t.Errorf("extension %d changed with what the view returned", i)
		}
	}
	if !v.PublicKey().Equal(&csr.Key.PublicKey) {
		t.Error("the key of the view changed with the key it returned")
	}

	// And it is the request that is issued: the subject, the key and the extensions of the view are those
	// of the certificate.
	root := buildRoot(t, nil)
	p := root.interParams(csr)
	p.CSR = v.DER()
	tbs, err := intermediateTBS(t, p)
	if err != nil {
		t.Fatal(err)
	}
	cert := parseBodyOf(t, tbs)
	if !bytes.Equal(cert.RawSubject, v.Subject()) {
		t.Error("the subject issued is not the subject of the view")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(v.PublicKey()) {
		t.Error("the key issued is not the key of the view")
	}
	for _, e := range v.Extensions() {
		if e.Id.Equal(oidBasicConstraints) { // written from the constant that the request must have
			continue
		}
		got := extensionOf(cert, e.Id)
		if got == nil || got.Critical != e.Critical || !bytes.Equal(got.Value, e.Value) {
			t.Errorf("the extension %s issued is not the one of the view", e.Id)
		}
	}
	// The view of a nil request is nothing.
	var none *pki.Request
	if none.DER() != nil || none.Subject() != nil || none.PublicKey() != nil || none.Extensions() != nil {
		t.Error("the view of nothing is something")
	}
}

// An edited request does not verify: the bytes that were signed are the bytes that are read.
func TestAnEditedRequestIsRefused(t *testing.T) {
	root := buildRoot(t, nil)
	good := goodRequest(t)
	der := good.DER()
	for name, edit := range map[string]func([]byte){
		"the subject":             func(d []byte) { d[bytes.Index(d, []byte("acme example ca"))] ^= 0x02 },
		"a name constraint":       func(d []byte) { d[bytes.Index(d, []byte("example.org"))] ^= 0x01 },
		"the key":                 func(d []byte) { d[bytes.Index(d, []byte{0x04})+70] ^= 0x01 },
		"a byte of the signature": func(d []byte) { d[len(d)-5] ^= 0x01 },
		"the attributes tag": func(d []byte) {
			spki := good.SPKI()
			d[bytes.Index(d, spki)+len(spki)] = 0xa1
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := append([]byte(nil), der...)
			edit(d)
			p := root.interParams(&testCSR{Fixed: d})
			tbs, err := intermediateTBS(t, p)
			refused(t, err, pki.ErrRequest)
			if tbs != nil {
				t.Error("a body came with the error")
			}
		})
	}
	t.Run("an empty request", func(t *testing.T) {
		p := root.interParams(goodRequest(t))
		p.CSR = nil
		_, err := intermediateTBS(t, p)
		refused(t, err, pki.ErrParams)
	})
	t.Run("text instead of a request", func(t *testing.T) {
		p := root.interParams(goodRequest(t))
		p.CSR = []byte("-----BEGIN CERTIFICATE REQUEST-----")
		_, err := intermediateTBS(t, p)
		refused(t, err, pki.ErrRequest)
	})
	_ = pkix.Extension{}
}

// The length of an ECDSA signature in DER varies by an octet or two, so a request of an exact size is made by signing again
// until it has that size. The size is made with the value of one attribute of a type that the module does not define, which
// has no upper bound (a subject of the request that is valid in every other way: the good extensions, and a common name beside
// it): a request of that size is read to its end by every rule of ParseRequest. (Before the extended key usage was required the size was made with an extended
// key usage of many object identifiers, which is refused now: only serverAuth and clientAuth may be named.)
func exactRequest(t testing.TB, size int) []byte {
	t.Helper()
	good := goodRequest(t)
	pad := mustOID(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7})
	build := func(n int) []byte {
		c := copyCSR(good)
		c.RawSubject = nameOf(rdn(atv(pad, tlv(tUTF8, bytes.Repeat([]byte("a"), n)))), rdn(atv(oidAttrCN, str(tUTF8, "acme"))))
		return c.DER()
	}
	n := size - len(build(0))
	for try := 0; try < 3000; try++ {
		der := build(n)
		diff := size - len(der)
		if diff == 0 {
			return der
		}
		n += diff
	}
	t.Fatalf("could not make a request of exactly %d octets", size)
	return nil
}

// withElementAfterTheAlgorithm is a SubjectPublicKeyInfo with one more element inside the sequence of its algorithm.
// withKeyElement is a SubjectPublicKeyInfo whose second element (the bit string) is replaced by what f makes of it.
func withKeyElement(t *testing.T, spki []byte, f func(asn1.RawValue) []byte) []byte {
	t.Helper()
	var info struct{ Algorithm, Key asn1.RawValue }
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		t.Fatal(err)
	}
	return tlv(0x30, info.Algorithm.FullBytes, f(info.Key))
}

func withAlgorithmOnly(t *testing.T, spki []byte) []byte {
	t.Helper()
	var info struct{ Algorithm, Key asn1.RawValue }
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		t.Fatal(err)
	}
	return tlv(0x30, info.Algorithm.FullBytes)
}

func withAlgorithmOf(t *testing.T, spki []byte, f func(asn1.RawValue) []byte) []byte {
	t.Helper()
	var info struct{ Algorithm, Key asn1.RawValue }
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		t.Fatal(err)
	}
	return tlv(0x30, f(info.Algorithm), info.Key.FullBytes)
}

func withElementAfterTheAlgorithm(t *testing.T, spki []byte) []byte {
	t.Helper()
	var info struct{ Algorithm, Key asn1.RawValue }
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		t.Fatal(err)
	}
	return tlv(0x30, tlv(0x30, info.Algorithm.Bytes, tlv(0x05)), info.Key.FullBytes)
}
