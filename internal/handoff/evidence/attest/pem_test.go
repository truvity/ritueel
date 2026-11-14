package attest_test

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"ritueel.id/ritueel/internal/handoff/evidence/attest"
)

// Two certificates that parse, for the blocks of a PEM file of pinned certificates.
func pemCerts(t testing.TB) (a, b []byte) {
	t.Helper()
	return selfSigned(t, 0, nil), selfSigned(t, 0, nil)
}

// The doc comment of CertificatesFromPEM: one or more blocks labelled CERTIFICATE and nothing else but
// line ends (CR and LF) around and between them. The blocks come back in order, as DER.
func TestCertificatesFromPEMReadsGoodFiles(t *testing.T) {
	a, b := pemCerts(t)
	one := pemOf("CERTIFICATE", a)
	two := append(bytes.Clone(one), pemOf("CERTIFICATE", b)...)

	got, err := attest.CertificatesFromPEM(one)
	if err != nil || len(got) != 1 || !bytes.Equal(got[0], a) {
		t.Fatalf("one block: %v, %d blocks", err, len(got))
	}
	got, err = attest.CertificatesFromPEM(two)
	if err != nil || len(got) != 2 || !bytes.Equal(got[0], a) || !bytes.Equal(got[1], b) {
		t.Fatalf("two blocks: %v, %d blocks", err, len(got))
	}

	crlf := func(p []byte) []byte { return bytes.ReplaceAll(p, []byte("\n"), []byte("\r\n")) }
	for name, text := range map[string][]byte{
		"LF line ends":                          two,
		"CRLF line ends":                        crlf(two),
		"CRLF with no line end at the very end": bytes.TrimRight(crlf(two), "\r\n"),
		"no line end at the very end":           bytes.TrimRight(two, "\n"),
		"blank lines between the blocks":        append(append(bytes.Clone(one), "\n\n\r\n\r\n"...), pemOf("CERTIFICATE", b)...),
		"line ends before the first block":      append([]byte("\n\r\n\n"), two...),
		"line ends after the last block":        append(bytes.Clone(two), "\n\r\n\n"...),
		"a lone CR between the blocks":          append(append(bytes.Clone(one), '\r'), pemOf("CERTIFICATE", b)...),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := attest.CertificatesFromPEM(text)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 2 || !bytes.Equal(got[0], a) || !bytes.Equal(got[1], b) {
				t.Fatalf("%d blocks, or not the two certificates in order", len(got))
			}
		})
	}
}

// Every damaged or foreign text is refused, with no result beside the error.
func TestCertificatesFromPEMRefusesWhatIsNotOnlyCertificates(t *testing.T) {
	a, b := pemCerts(t)
	good := pemOf("CERTIFICATE", a)
	good2 := pemOf("CERTIFICATE", b)
	two := append(bytes.Clone(good), good2...)

	// Blocks that carry bytes that are not one DER certificate, in every way that one can fail.
	trailing := append(bytes.Clone(a), 0x00)
	truncated := a[:len(a)-10]
	notCert := []byte{0x30, 0x01, 0x01}
	emptyBlock := []byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
	badBase64 := []byte("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")
	wrongTag := bytes.Clone(a) // the same length, with the tag of a SET where a SEQUENCE belongs
	wrongTag[0] = 0x31

	bad := map[string][]byte{
		"empty":                    {},
		"line ends only":           []byte("\r\n\n"),
		"text only":                []byte("hello"),
		"non UTF-8 bytes":          {0xff, 0xfe, 0x00},
		"NUL bytes":                bytes.Repeat([]byte{0}, 100),
		"an end line only":         []byte("-----END CERTIFICATE-----\n"),
		"a begin line only":        []byte("-----BEGIN CERTIFICATE-----"),
		"a block that never ends":  append([]byte("-----BEGIN CERTIFICATE-----\n"), good[len("-----BEGIN CERTIFICATE-----\n"):bytes.Index(good, []byte("-----END"))]...),
		"an empty block":           emptyBlock,
		"bad Base64 in a block":    badBase64,
		"bytes that are no DER":    pemOf("CERTIFICATE", notCert),
		"bytes after the DER":      pemOf("CERTIFICATE", trailing),
		"a DER that is cut short":  pemOf("CERTIFICATE", truncated),
		"a DER of the wrong tag":   pemOf("CERTIFICATE", wrongTag),
		"Base64 on one long line":  []byte("-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(notCert) + "\n-----END CERTIFICATE-----\n"),
		"a block with a header":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: a}),
		"a header then a good one": append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"X-Note": "a"}, Bytes: a}), good2...),
		"a good block then a header": append(bytes.Clone(good),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"X-Note": "a"}, Bytes: b})...),

		// Text outside the blocks. Only CR and LF may stand there: a space or a tab does not.
		"text before a block":                                append([]byte("note\n"), good...),
		"text between blocks":                                append(append(bytes.Clone(good), "note\n"...), good2...),
		"text after a block":                                 append(bytes.Clone(good), "note\n"...),
		"a space before a block":                             append([]byte(" "), good...),
		"a tab before a block":                               append([]byte("\t"), good...),
		"a space between blocks":                             append(append(bytes.Clone(good), ' '), good2...),
		"a tab between blocks":                               append(append(bytes.Clone(good), "\t\n"...), good2...),
		"a space after the last block":                       append(bytes.Clone(two), ' '),
		"a tab after the last block":                         append(bytes.Clone(two), '\t'),
		"a NUL after the last block":                         append(bytes.Clone(two), 0),
		"a text line before a block that looks like a start": append([]byte("-----BEGIN NOTE-----\n"), good...),

		// Blocks of another label.
		"a private key block":     pemOf("PRIVATE KEY", a),
		"an EC private key block": pemOf("EC PRIVATE KEY", a),
		"a request block":         pemOf("CERTIFICATE REQUEST", a),
		"a public key block":      pemOf("PUBLIC KEY", a),
		"a trusted certificate":   pemOf("TRUSTED CERTIFICATE", a),
		"an X509 certificate":     pemOf("X509 CERTIFICATE", a),
		"a lower-case label":      pemOf("certificate", a),
		"a good block then a key": append(bytes.Clone(good), pemOf("PRIVATE KEY", a)...),
		"a key then a good block": append(pemOf("PRIVATE KEY", a), good...),

		// A damaged block is an error even when a good block follows it or comes before it.
		"a block that is not a DER, then a good block":  append(pemOf("CERTIFICATE", notCert), good...),
		"bad Base64, then a good block":                 append(bytes.Clone(badBase64), good...),
		"an empty block, then a good block":             append(bytes.Clone(emptyBlock), good...),
		"a cut DER, then a good block":                  append(pemOf("CERTIFICATE", truncated), good...),
		"bytes after the DER, then a good block":        append(pemOf("CERTIFICATE", trailing), good...),
		"a good block, then bad Base64":                 append(bytes.Clone(good), badBase64...),
		"a good block, then a block that is not a DER":  append(bytes.Clone(good), pemOf("CERTIFICATE", notCert)...),
		"a good block, then an empty block":             append(bytes.Clone(good), emptyBlock...),
		"a good block, a damaged one, a good one":       append(append(bytes.Clone(good), badBase64...), good2...),
		"a begin line, then a good block":               append([]byte("-----BEGIN CERTIFICATE-----\n"), good...),
		"a begin line with no end, then a good block":   append([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n"), good...),
		"a good block, a begin line, then a good block": append(append(bytes.Clone(good), "-----BEGIN CERTIFICATE-----\n"...), good2...),
	}
	for name, text := range bad {
		t.Run(name, func(t *testing.T) {
			got, err := attest.CertificatesFromPEM(text)
			if err == nil {
				t.Fatalf("read %d blocks", len(got))
			}
			if got != nil {
				t.Error("a result beside an error")
			}
		})
	}
}

// Sixty-four blocks are read and the sixty-fifth is not; 1 MiB of text is read and one byte more is not.
func TestCertificatesFromPEMIsBounded(t *testing.T) {
	a, _ := pemCerts(t)
	block := pemOf("CERTIFICATE", a)

	if got, err := attest.CertificatesFromPEM(bytes.Repeat(block, attest.MaxPinned)); err != nil || len(got) != attest.MaxPinned {
		t.Errorf("%d blocks: %v, %d read", attest.MaxPinned, err, len(got))
	}
	if got, err := attest.CertificatesFromPEM(bytes.Repeat(block, attest.MaxPinned+1)); err == nil {
		t.Errorf("%d blocks were read", len(got))
	}
	// Line ends do not count against the blocks, and the text is measured in bytes.
	atLimit := append(bytes.Clone(block), bytes.Repeat([]byte("\n"), 1<<20-len(block))...)
	if len(atLimit) != 1<<20 {
		t.Fatalf("test setup: %d bytes", len(atLimit))
	}
	if got, err := attest.CertificatesFromPEM(atLimit); err != nil || len(got) != 1 {
		t.Errorf("a text of 1 MiB: %v", err)
	}
	if got, err := attest.CertificatesFromPEM(append(atLimit, '\n')); err == nil || got != nil {
		t.Errorf("a text of 1 MiB and a byte was read: %v", err)
	}
	if _, err := attest.CertificatesFromPEM(bytes.Repeat([]byte("A"), 4<<20)); err == nil {
		t.Error("4 MiB of text was read")
	}
}
