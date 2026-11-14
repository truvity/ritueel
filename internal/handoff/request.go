package handoff

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"

	"ritueel.id/ritueel/internal/fsx"
)

// The suffixes of the files of a request, as the keys of [Request.Files] ("Messages and files"). A file
// is `<stem>.<suffix>`.
const (
	// FileProof is the proof file, `<stem>.proof.json`, which every request has.
	FileProof = "proof.json"
	// FileCSR is the certificate request, `<stem>.csr.pem`, of an x509-intermediate.
	FileCSR = "csr.pem"
	// FileSubkey is the public subkey with its back-signatures, `<stem>.subkey.pgp`, of an openpgp-subkey.
	FileSubkey = "subkey.pgp"
	// FileSSHKey is the OpenSSH public key line, `<stem>.sshca.pub`, of an ssh-ca-key.
	FileSSHKey = "sshca.pub"
	// FileSSHSig is the SSH signature, `<stem>.sshca.sig`, of an ssh-ca-key.
	FileSSHSig = "sshca.sig"
)

// requestSuffixes are the files that LoadRequest looks for.
var requestSuffixes = []string{FileProof, FileCSR, FileSubkey, FileSSHKey, FileSSHSig}

// ErrNoProof is wrapped by the error of [LoadRequest] when `<stem>.proof.json` is not there. The
// request has no proof file, so there is no request to judge.
var ErrNoProof = errors.New("handoff: the request has no proof file")

// ErrLoad is wrapped by every other error of [LoadRequest]: a stem that is not a stem, a folder that is
// not a path, a file that cannot be read, a link anywhere on the way to a file, and a folder or any file that
// is not a regular file where a file belongs. It is the caller's
// problem and not a verdict on the request.
var ErrLoad = errors.New("handoff: the files of the request cannot be read")

// Request is the files of one request, by suffix. Nothing is parsed here.
type Request struct {
	// Stem is the name that the requester chose, lower-case letters, digits and hyphens.
	Stem string
	// Files holds the content of each file of the request by its suffix: "proof.json", "csr.pem",
	// "subkey.pgp", "sshca.pub" and "sshca.sig". A file that is not there has no entry.
	Files map[string][]byte
}

// LoadRequest reads the files named `<stem>.<suffix>` in the folder dir of root and returns them by
// suffix. dir is relative to root, with "/" as the separator, and is requests/<stem> of a bundle; "." is
// root itself. A file of any other name, and the files of an answer, are not read.
//
// Every read is made by [fsx.ReadFile], which walks the path from the open folder root one element at a
// time and opens each element without following a link (openat with O_NOFOLLOW), so no element of the
// path is followed when it is a link, a folder included, and not only the last. A file is opened without
// waiting, so a pipe that stands where a file belongs does not block the call, and it is read only when
// the open file is a regular file. A link, a folder, a pipe, a socket, a device, or any other file that is
// not a regular file where a file belongs, and a file that cannot be read, is an error ([ErrLoad]). A
// missing `<stem>.proof.json`, or a folder that is not there, is an error too ([ErrNoProof]) and not a
// verdict: with no proof file there is no request.
//
// The folder root is the caller's choice and is opened as the caller wrote it (see [fsx.OpenFS]); what is
// below it is not trusted, and what a process that can write into root does while the call runs is the
// package fsx's own condition, which its comment states. The function takes an fsx.FS and not an fs.FS
// because an fs.FS has no call that opens without following a link or without waiting, so it cannot give
// the two promises above.
//
// A file longer than [MaxFileSize] is not an error of the caller: the request is refused, because the
// contract refuses a file that large before it reads it, and the refusal is the verdict's (malformed). So
// a file of up to [fsx.MaxReadSize] bytes is returned cut to MaxFileSize+1 bytes, which is more than the
// limit, and [Checker.Check] refuses it. A file longer than fsx.MaxReadSize is read in no part by fsx, and
// is given the same answer: it is returned as MaxFileSize+1 bytes of zeros, which Check refuses as
// malformed. Its content is never needed, because the file is refused before it is read.
func LoadRequest(root fsx.FS, dir, stem string) (*Request, error) {
	if root == nil {
		return nil, fmt.Errorf("%w: no root folder", ErrLoad)
	}
	if !validStem(stem) {
		return nil, fmt.Errorf("%w: the stem is not 1 to 63 lower-case letters, digits and hyphens that start with a letter or a digit", ErrLoad)
	}
	if !fs.ValidPath(dir) {
		return nil, fmt.Errorf("%w: the folder is not a path inside the root", ErrLoad)
	}
	r := &Request{Stem: stem, Files: map[string][]byte{}}
	for _, suffix := range requestSuffixes {
		data, err := fsx.ReadFile(root, path.Join(dir, stem+"."+suffix))
		switch {
		case errors.Is(err, fs.ErrNotExist) && suffix != FileProof:
			continue
		case errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("%w: %s.%s", ErrNoProof, stem, suffix)
		case errors.Is(err, fsx.ErrTooLarge):
			// A file over the read limit of fsx is read in no part; the contract refuses a file over
			// MaxFileSize before it is read, so it is given the same answer as a file just over that limit:
			// MaxFileSize+1 bytes of nothing, which Check refuses as malformed.
			data = make([]byte, MaxFileSize+1)
		case err != nil:
			return nil, fmt.Errorf("%w: %s.%s: %w", ErrLoad, stem, suffix, err)
		}
		if len(data) > MaxFileSize+1 {
			data = slices.Clone(data[:MaxFileSize+1])
		}
		r.Files[suffix] = data
	}
	return r, nil
}

// validStem is the stem of the contract: lower-case letters, digits and hyphens, 1 to 63 characters,
// starting with a letter or a digit.
func validStem(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i > 0:
		default:
			return false
		}
	}
	return true
}

// Proof is the proof file read: `<stem>.proof.json` ("The proof file"). A member that the type does
// not have is empty (nil for a list).
type Proof struct {
	// Handoff is the contract version.
	Handoff int
	// Type is the type of the request.
	Type Type
	// RequestSHA256 is the digest of the request in lower-case hexadecimal.
	RequestSHA256 string
	// Store is where the key lives.
	Store Store
	// Evidence is the member evidence, the bytes of one JSON object whose shape has been checked for the
	// store; its content is read by the verifiers. Nil for a software key.
	Evidence json.RawMessage
	// Primaries are the fingerprints of the active primaries, an openpgp-subkey only.
	Primaries []string
	// Capabilities is the one capability of an openpgp-subkey, sign or authenticate.
	Capabilities []string
	// Use is user or host, an ssh-ca-key only.
	Use string

	// kmsKey is the DER of the public_key member of the evidence of an aws-kms proof, Base64 decoded. The
	// checker compares it with the key of the request (check 8). Nil for any other store.
	kmsKey []byte
}

// clone returns a copy that shares nothing with p.
func (p *Proof) clone() *Proof {
	c := *p
	c.Evidence = slices.Clone(p.Evidence)
	c.Primaries = slices.Clone(p.Primaries)
	c.Capabilities = slices.Clone(p.Capabilities)
	c.kmsKey = slices.Clone(p.kmsKey)
	return &c
}

// copyRequest returns a request that shares no memory with r, so that what a verifier does to its copy
// has no effect on the checks that follow.
func copyRequest(r *Request) *Request {
	c := &Request{Stem: r.Stem, Files: make(map[string][]byte, len(r.Files))}
	for k, v := range r.Files {
		c.Files[k] = slices.Clone(v)
	}
	return c
}
