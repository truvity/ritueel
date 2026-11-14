package software

import (
	"bytes"
	"io"
	"reflect"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// The wording of a test root's key files (docs/reference/bundle.md, "The software root's key
// files"; proposed, issue 136), in one place.
const (
	// testMarker is the first line of a test root's X.509 key file.
	testMarker = "TEST ONLY: a test root with no passphrase; anyone with this file can sign as this root."
	// armorComment is the value of the one armour header of a test root's OpenPGP files.
	armorComment = "TEST ONLY"
	// armorKeyBlock and armorSigBlock are the armour types.
	armorKeyBlock = "PGP PRIVATE KEY BLOCK"
	armorSigBlock = "PGP SIGNATURE"
)

// format wraps the payload of a key file into the bytes of the file, and unwraps it. The mode of a
// Store picks the format; a test replaces it to see what the Store hands to it. The format of a
// test root is [plainFormat].
type format interface {
	// wrap returns the bytes of the file for a payload.
	wrap(kind FileKind, payload []byte) ([]byte, error)
	// unwrap returns the payload of a file, which has passed the check of its size and mode.
	unwrap(kind FileKind, file []byte) ([]byte, error)
}

// plainFormat is the format of a test root: no encryption, and the words that say so.
type plainFormat struct{}

func (plainFormat) wrap(kind FileKind, payload []byte) ([]byte, error) {
	switch kind {
	case FileX509:
		return append([]byte(testMarker+"\n"), payload...), nil
	case FileOpenPGP:
		return armorEncode(armorKeyBlock, payload)
	case FileRevocation:
		return armorEncode(armorSigBlock, payload)
	case FileRemoval:
		return bytes.Clone(payload), nil
	}
	return nil, refuse(ErrParams, "the kind of file is not one of the four")
}

// unwrap reads a file of a test root. A missing final newline is accepted; any other deviation is
// an [ErrKeyFile].
func (plainFormat) unwrap(kind FileKind, file []byte) ([]byte, error) {
	switch kind {
	case FileX509:
		rest, ok := bytes.CutPrefix(file, []byte(testMarker+"\n"))
		if !ok {
			return nil, refuse(ErrKeyFile, "the file does not start with the TEST ONLY marker line")
		}
		return withFinalNewline(rest), nil
	case FileOpenPGP:
		return armorDecode(armorKeyBlock, file)
	case FileRevocation:
		return armorDecode(armorSigBlock, file)
	case FileRemoval:
		return bytes.Clone(file), nil
	}
	return nil, refuse(ErrParams, "the kind of file is not one of the four")
}

// withFinalNewline returns b with one final LF added when it has none.
func withFinalNewline(b []byte) []byte {
	if bytes.HasSuffix(b, []byte("\n")) {
		return bytes.Clone(b)
	}
	return append(bytes.Clone(b), '\n')
}

// armorEncode writes data as one armour block of a type, with the one header of a test root and the
// checksum, and a final LF.
func armorEncode(blockType string, data []byte) ([]byte, error) {
	var b bytes.Buffer
	w, err := armor.Encode(&b, blockType, map[string]string{"Comment": armorComment})
	if err != nil {
		return nil, refuse(ErrKeyFile, "the armour could not be written")
	}
	if _, err := w.Write(data); err != nil {
		return nil, refuse(ErrKeyFile, "the armour could not be written")
	}
	if err := w.Close(); err != nil {
		return nil, refuse(ErrKeyFile, "the armour could not be written")
	}
	// go-crypto ends the block at the last dash, with no line end; a file ends with one LF.
	b.WriteByte('\n')
	return b.Bytes(), nil
}

// armorDecode reads exactly what [armorEncode] writes: one block of the type, the header
// `Comment: TEST ONLY` and no other, a valid checksum, and nothing after the end line except one
// LF. The block is read with go-crypto and written again, and the two texts must be the same.
func armorDecode(blockType string, file []byte) ([]byte, error) {
	text := withFinalNewline(file)
	blk, err := armor.Decode(bytes.NewReader(text))
	if err != nil || blk == nil || blk.Type != blockType {
		return nil, refuse(ErrKeyFile, "the file is not one armour block of the type of the page")
	}
	if !reflect.DeepEqual(blk.Header, map[string]string{"Comment": armorComment}) {
		return nil, refuse(ErrKeyFile, "the armour header is not exactly Comment: TEST ONLY")
	}
	body, err := io.ReadAll(io.LimitReader(blk.Body, MaxKeyFileSize+1))
	if err != nil || len(body) > MaxKeyFileSize {
		return nil, refuse(ErrKeyFile, "the armour body does not read, or its checksum is wrong")
	}
	again, err := armorEncode(blockType, body)
	if err != nil || !bytes.Equal(again, text) {
		clear(body)
		return nil, refuse(ErrKeyFile, "the armour is not exactly one block of the page and nothing else")
	}
	return body, nil
}
