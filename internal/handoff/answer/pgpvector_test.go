package answer_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff/answer"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/testrepo"
)

// A reader of OpenPGP packets for the tests, written apart from package openpgp.

// readPGPPacket returns the tag, the body and the rest of the first packet of b (old or new header form, a
// length that is stated).
func readPGPPacket(t testing.TB, b []byte) (tag byte, body, rest []byte) {
	t.Helper()
	if len(b) < 2 || b[0]&0x80 == 0 {
		t.Fatalf("not a packet: % x", b[:min(len(b), 4)])
	}
	var n, hdr int
	if b[0]&0x40 != 0 {
		tag = b[0] & 0x3f
		switch {
		case b[1] < 192:
			n, hdr = int(b[1]), 2
		case b[1] < 224:
			n, hdr = (int(b[1])-192)<<8+int(b[2])+192, 3
		case b[1] == 255:
			n, hdr = int(binary.BigEndian.Uint32(b[2:6])), 6
		default:
			t.Fatalf("a partial length")
		}
	} else {
		tag = b[0] >> 2 & 0x0f
		switch b[0] & 3 {
		case 0:
			n, hdr = int(b[1]), 2
		case 1:
			n, hdr = int(binary.BigEndian.Uint16(b[1:3])), 3
		case 2:
			n, hdr = int(binary.BigEndian.Uint32(b[1:5])), 5
		default:
			t.Fatalf("an indeterminate length")
		}
	}
	if len(b) < hdr+n {
		t.Fatalf("a packet cut short")
	}
	return tag, b[hdr : hdr+n], b[hdr+n:]
}

// readSubpackets reads a run of subpackets of a signature.
func readSubpackets(t testing.TB, area []byte) []subpacket {
	t.Helper()
	var out []subpacket
	for len(area) > 0 {
		var n, hdr int
		switch {
		case area[0] < 192:
			n, hdr = int(area[0]), 1
		case area[0] < 255:
			n, hdr = (int(area[0])-192)<<8+int(area[1])+192, 2
		default:
			n, hdr = int(binary.BigEndian.Uint32(area[1:5])), 5
		}
		if n < 1 || len(area) < hdr+n {
			t.Fatalf("a subpacket cut short")
		}
		out = append(out, subpacket{typ: area[hdr] & 0x7f, critical: area[hdr]&0x80 != 0, data: bytes.Clone(area[hdr+1 : hdr+n])})
		area = area[hdr+n:]
	}
	return out
}

// splitSignature reads the body of a version 4 signature into its hashed and unhashed subpackets and the rest.
func splitSignature(t testing.TB, body []byte) (head []byte, hashed, unhashed []subpacket, tail []byte) {
	t.Helper()
	if len(body) < 6 || body[0] != 4 {
		t.Fatalf("not a version 4 signature")
	}
	hl := int(binary.BigEndian.Uint16(body[4:6]))
	hashed = readSubpackets(t, body[6:6+hl])
	ul := int(binary.BigEndian.Uint16(body[6+hl : 8+hl]))
	unhashed = readSubpackets(t, body[8+hl:8+hl+ul])
	return body[:6+hl], hashed, unhashed, body[8+hl+ul:]
}

// withEmbedded writes the signature packet again with the data of its embedded-signature subpacket replaced. The
// unhashed area is not signed, so the signature still verifies.
func withEmbedded(t testing.TB, sigPacket, embedded []byte) []byte {
	t.Helper()
	tag, body, rest := readPGPPacket(t, sigPacket)
	if tag != pgpTagSignature || len(rest) != 0 {
		t.Fatalf("not one signature packet")
	}
	head, _, unhashed, tail := splitSignature(t, body)
	changed := 0
	for i := range unhashed {
		if unhashed[i].typ == spEmbedded {
			unhashed[i].data = embedded
			changed++
		}
	}
	if changed != 1 {
		t.Fatalf("%d embedded signatures in the binding", changed)
	}
	area := subpackets(unhashed)
	out := bytes.Clone(head)
	out = binary.BigEndian.AppendUint16(out, uint16(len(area)))
	out = append(out, area...)
	out = append(out, tail...)
	return pgpPacket(pgpTagSignature, out)
}

// The vector answer that the second primary of the request made, with the back-signature in its binding changed
// for the back-signature that the request holds for the first primary. The signature of the binding verifies
// all the same (the embedded signature is not signed), the issuer and the key are right, and the digest of the
// artifact is made again, so that the only thing wrong with the answer is the embedded signature: it is the
// one of another primary. Check 6 refuses it with the code profile.
func TestAnAnswerThatEmbedsTheBackSignatureOfAnotherPrimaryIsRefusedAtTheProfile(t *testing.T) {
	m := readVectorManifest(t)
	chk := mustChecker(t, vectorConfig(t, m))
	c := vectorCase(t, "pgp-response-other-primary")
	asked := vectorAsked(t, c)
	control := vectorAnswer(t, c)
	v, err := chk.Check(asked, control)
	want(t, v, err, "", pOK)

	// The request: the subkey packet, then one back-signature for each primary, in the order of the proof.
	var proof struct {
		Primaries []string `json:"primaries"`
	}
	if err := json.Unmarshal(testrepo.Read(t, vectorsDir, "requests/pgp-response-request.proof.json"), &proof); err != nil || len(proof.Primaries) != 2 {
		t.Fatalf("%v, primaries %v", err, proof.Primaries)
	}
	if v.Info.Issuer != proof.Primaries[1] {
		t.Fatalf("the answer is by %s, the second primary of the proof is %s", v.Info.Issuer, proof.Primaries[1])
	}
	file := testrepo.Read(t, vectorsDir, "requests/pgp-response-request.subkey.pgp")
	tag, _, rest := readPGPPacket(t, file)
	if tag != pgpTagSubkey {
		t.Fatalf("the first packet of the request is %d", tag)
	}
	var backs [][]byte
	for len(rest) > 0 {
		var body []byte
		tag, body, rest = readPGPPacket(t, rest)
		if tag != pgpTagSignature {
			t.Fatalf("a packet of tag %d after the subkey", tag)
		}
		backs = append(backs, body)
	}
	if len(backs) != 2 || bytes.Equal(backs[0], backs[1]) {
		t.Fatalf("%d back-signatures in the request, or two that are one", len(backs))
	}
	own, other := backs[1], backs[0]

	sub, binding, err := openpgp.SplitBoundFile(control.Files[answer.FileBound])
	if err != nil {
		t.Fatal(err)
	}
	// embeds is the answer with the embedded signature of the binding replaced; with digest, the digest of the
	// artifact in the result file is written again.
	embeds := func(embedded []byte, digest bool) *answer.Answer {
		a := cloneAnswer(control)
		a.Files[answer.FileBound] = append(bytes.Clone(sub), withEmbedded(t, binding, embedded)...)
		if digest {
			old, now := sha256Hex(control.Files[answer.FileBound]), sha256Hex(a.Files[answer.FileBound])
			if !bytes.Contains(a.Files[answer.FileResult], []byte(old)) {
				t.Fatal("the result file does not hold the digest of the bound file")
			}
			a.Files[answer.FileResult] = bytes.Replace(a.Files[answer.FileResult], []byte(old), []byte(now), 1)
		}
		return a
	}
	t.Run("the rewrite with its own back-signature is accepted: the rewrite is faithful", func(t *testing.T) {
		v, err := chk.Check(asked, embeds(own, true))
		want(t, v, err, "", pOK)
	})
	t.Run("the back-signature that the request holds for the other primary", func(t *testing.T) {
		v, err := chk.Check(asked, embeds(other, true))
		want(t, v, err, answer.CodeProfile, pst6)
		if !strings.Contains(v.Detail, "embedded signature") {
			t.Errorf("detail %q", v.Detail)
		}
		if v.Info != nil || v.Accepted() || !v.AnswerRefused() {
			t.Error("accepted, or not the refusal of an answer")
		}
	})
	t.Run("the digest of the artifact not made again: check 6 comes before the digests of check 8", func(t *testing.T) {
		v, err := chk.Check(asked, embeds(other, false))
		want(t, v, err, answer.CodeProfile, pst6)
	})
}
