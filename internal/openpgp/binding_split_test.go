package openpgp_test

import (
	"bytes"
	"errors"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// SplitBoundFile reads `<stem>.bound.pgp`: exactly two whole packets, a Public-Subkey packet (tag
// 14) and then a Signature packet (tag 2), and nothing else (docs/reference/hand-off-contract.md,
// "What comes back").

// maxBoundFile is the 256 KiB of a file of the contract.
const maxBoundFile = 256 * 1024

func TestSplitBoundFileSplitsTheFileIntoItsTwoPacketsAsTheyAre(t *testing.T) {
	k := newBindKit(t)
	sig := k.build(t, nil)
	sigOld := k.build(t, func(sp *sigSpec) { sp.OldHeader = true })
	sub5 := wrapLong(tagSubkey, k.sub.body())
	subOld := oldHeader(tagSubkey, k.sub.body())
	sig5 := wrapLong(tagSignature, bodyOf(t, sig))
	garbage := wrap(tagSignature, []byte{0xFF, 0x00, 0x42}) // nothing of the signature is read here
	for _, c := range []struct {
		name     string
		sub, sig []byte
	}{
		{"the packets of BindSubkey", k.sub.Packet, sig},
		{"a five-byte length on both", sub5, sig5},
		{"old-format headers on both", subOld, sigOld},
		{"old-format subkey, new-format signature", subOld, sig},
		{"new-format subkey, old-format signature", k.sub.Packet, sigOld},
		{"a signature packet that is no signature", k.sub.Packet, garbage},
		{"an empty signature packet", k.sub.Packet, wrap(tagSignature, nil)},
		{"an empty subkey packet", wrap(tagSubkey, nil), sig},
	} {
		t.Run(c.name, func(t *testing.T) {
			file := append(bytes.Clone(c.sub), c.sig...)
			in := bytes.Clone(file)
			gotSub, gotSig, err := openpgp.SplitBoundFile(file)
			if err != nil {
				t.Fatalf("SplitBoundFile: %v", err)
			}
			if !bytes.Equal(gotSub, c.sub) || !bytes.Equal(gotSig, c.sig) {
				t.Error("the two packets are not the two packets of the file, each whole with its header, as it was written")
			}
			// Copies: changing what came back changes nothing in the file, and the reverse.
			clear(gotSub)
			clear(gotSig)
			if !bytes.Equal(file, in) {
				t.Error("changing the returned packets changed the file")
			}
			again, againSig, err := openpgp.SplitBoundFile(file)
			if err != nil {
				t.Fatal(err)
			}
			clear(file)
			if !bytes.Equal(again, c.sub) || !bytes.Equal(againSig, c.sig) {
				t.Error("changing the file changed the returned packets")
			}
		})
	}
}

func TestSplitBoundFileRefusesWhatIsNotExactlyASubkeyPacketAndASignaturePacket(t *testing.T) {
	k := newBindKit(t)
	sig := k.build(t, nil)
	sub := k.sub.Packet
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	// A partial length (a first length byte of 224 to 254) is no length, even when the four bytes
	// after it would be a good five-byte length.
	partial := func(tag byte, first byte, body []byte) []byte {
		return join([]byte{0xC0 | tag, first}, u32(uint32(len(body))), body)
	}
	subBody, sigBody := k.sub.body(), bodyOf(t, sig)
	longest := make([]byte, maxBoundFile+1)
	for _, c := range []struct {
		name string
		file []byte
	}{
		{"nil", nil},
		{"an empty file", []byte{}},
		{"one byte", []byte{0xCE}},
		{"a header with no length", []byte{0xCE}},
		{"the subkey packet only", sub},
		{"the signature packet only", sig},
		{"the signature and then the subkey", join(sig, sub)},
		{"three packets: subkey, signature, signature", join(sub, sig, sig)},
		{"three packets: subkey, subkey, signature", join(sub, sub, sig)},
		{"two subkeys", join(sub, sub)},
		{"two signatures", join(sig, sig)},
		{"a primary key packet and a signature", join(wrap(tagPublicKey, k.sub.body()), sig)},
		{"a user ID and a signature", join(wrap(tagUserID, []byte("Example Person")), sig)},
		{"a subkey and a user ID", join(sub, wrap(tagUserID, []byte("Example Person")))},
		{"a subkey and a primary key packet", join(sub, wrap(tagPublicKey, k.sub.body()))},
		{"a subkey and a secret subkey packet (tag 7)", join(sub, wrap(7, sig[3:]))},
		{"a subkey and a literal data packet", join(sub, wrap(11, sig[3:]))},
		{"a stray byte after the signature", join(sub, sig, []byte{0})},
		{"a stray header after the signature", join(sub, sig, []byte{0xC2})},
		{"the subkey packet and half of the signature", join(sub, sig[:len(sig)/2])},
		{"the subkey packet and the signature without its last byte", join(sub, sig[:len(sig)-1])},
		{"the signature header with no body", join(sub, sig[:2])},
		{"half of the subkey packet", sub[:len(sub)/2]},
		{"the subkey packet without its last byte", join(sub[:len(sub)-1], sig)},
		{"a stray byte between the packets", join(sub, []byte{0}, sig)},
		{"a stray byte in front", join([]byte{0}, sub, sig)},
		{"a header whose top bit is not set", join([]byte{0x4E, 0x01, 0x00}, sig)},
		{"a partial length on the subkey packet", join([]byte{0xCE, 0xE1}, sub[2:], sig)},
		{"a partial length of 224 that is followed by a five-byte length, on the subkey packet", join(partial(tagSubkey, 0xE0, subBody), sig)},
		{"a partial length of 254 that is followed by a five-byte length, on the subkey packet", join(partial(tagSubkey, 0xFE, subBody), sig)},
		{"a partial length of 224 that is followed by a five-byte length, on the signature packet", join(sub, partial(tagSignature, 0xE0, sigBody))},
		{"a partial length of 254 that is followed by a five-byte length, on the signature packet", join(sub, partial(tagSignature, 0xFE, sigBody))},
		{"a partial length on the signature packet", join(sub, []byte{0xC2, 0xE1}, sig[2:])},
		{"an indeterminate length on the subkey packet (old format)", join([]byte{0x80 | tagSubkey<<2 | 3}, sub[2:], sig)},
		{"an indeterminate length on the signature packet (old format)", join(sub, []byte{0x80 | tagSignature<<2 | 3}, sig[2:])},
		{"a length that runs past the end of the file", join(sub, []byte{0xC2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, sig[2:])},
		{"a five-byte length of 2^32-1", join(sub, []byte{0xC2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})},
		{"an old-format length that runs past the end", join(sub, []byte{0x80 | tagSignature<<2 | 2, 0x7F, 0xFF, 0xFF, 0xFF})},
		{"a longer file than 256 KiB", longest},
		{"a long file that starts with the two packets", join(sub, sig, make([]byte, maxBoundFile))},
		{"two packets and 256 KiB of zeros", join(sub, sig, make([]byte, 3*maxBoundFile))},
	} {
		gotSub, gotSig, err := openpgp.SplitBoundFile(c.file)
		if gotSub != nil || gotSig != nil || !errors.Is(err, openpgp.ErrBoundFile) || !errors.Is(err, openpgp.ErrAnswer) {
			t.Errorf("%s: SplitBoundFile = %d bytes, %d bytes, %v; want nothing and ErrBoundFile", c.name, len(gotSub), len(gotSig), err)
			continue
		}
		if errors.Is(err, openpgp.ErrBinding) || errors.Is(err, openpgp.ErrBindingShape) {
			t.Errorf("%s: the fault of a file is also a fault of a binding: %v", c.name, err)
		}
		checkErrorText(t, c.name, err)
	}
}

// The file is at most 256 KiB, a number that the contract gives for every file: a file of exactly
// that length is read, and one byte more is refused. The signature packet is not read here, so a
// body of any bytes holds the length.
func TestSplitBoundFileReadsAFileOfExactly256KiBAndRefusesOneByteMore(t *testing.T) {
	k := newBindKit(t)
	sub := k.sub.Packet
	fill := func(total int) []byte {
		// The signature packet has a five-byte length, so its header is 6 bytes.
		body := make([]byte, total-len(sub)-6)
		return append(bytes.Clone(sub), wrapLong(tagSignature, body)...)
	}
	file := fill(maxBoundFile)
	if len(file) != maxBoundFile {
		t.Fatalf("the test file has %d bytes", len(file))
	}
	gotSub, gotSig, err := openpgp.SplitBoundFile(file)
	if err != nil || !bytes.Equal(gotSub, sub) || len(gotSub)+len(gotSig) != maxBoundFile {
		t.Errorf("a file of 256 KiB: %d + %d bytes, %v; want it read", len(gotSub), len(gotSig), err)
	}
	if _, _, err := openpgp.SplitBoundFile(fill(maxBoundFile + 1)); !errors.Is(err, openpgp.ErrBoundFile) {
		t.Errorf("a file of 256 KiB and one byte: %v; want ErrBoundFile", err)
	}
	if _, _, err := openpgp.SplitBoundFile(fill(maxBoundFile - 1)); err != nil {
		t.Errorf("a file of 256 KiB less one byte: %v", err)
	}
}

func TestSplitBoundFileReadsTheVectorFilesAndRefusesTheRequestFiles(t *testing.T) {
	for _, v := range boundVectors {
		if _, _, err := openpgp.SplitBoundFile(boundFile(t, v.id)); err != nil {
			t.Errorf("%s: %v", v.id, err)
		}
	}
	// A request holds the subkey and the back-signatures: two of them, so it is not a bound file.
	for _, name := range vectorSubkeyFiles {
		file := subkeyFile(t, name.name)
		_, _, err := openpgp.SplitBoundFile(file)
		if name.signatures == 1 {
			// One signature: the shape of a bound file, whatever the signature is (it is read by VerifyBinding).
			if err != nil {
				t.Errorf("%s: %v", name.name, err)
			}
			continue
		}
		if !errors.Is(err, openpgp.ErrBoundFile) {
			t.Errorf("%s (%d signatures): SplitBoundFile = %v; want ErrBoundFile", name.name, name.signatures, err)
		}
	}
}
