// Package trustset makes the files of one trust set from the root keys of a bundle, and nothing
// else. The files are the three that the bundle page lists in "The layout" (record 0006, rule 12):
// root-list.json, root-list.jws and ca-bundle.pem, and the format of each is the one of
// docs/reference/root-list.md.
//
// What is built. [MarshalList] writes root-list.json in the canonical form of RFC 8785, with
// expires_at 13 months after signed_at (rootlist.ExpiresFor), the roots and the removals in label
// order. [MarshalCABundle] writes ca-bundle.pem from the certificates of the roots. [NewRemoval]
// writes the removal authorisation of a root key. [Signer] is one root key's signature, whatever
// key store holds the key, and [NewKeySigner] adapts a software key to it. [SetName] spells the
// folder name of a trust set. [FileNames], [FileMode] and the limits are in layout.go, the one
// place that names the files. The writer of the general JWS of root-list.jws is in jws.go and is
// reached through the signing of a draft, which is built next.
//
// The rules that run through the package:
//   - Nothing here is the judge of a list. The judge is package rootlist: every document is read
//     back with its reader (ParseList, CheckRemoval, VerifyCABundle, jws.ParseGeneral) before it is
//     returned, and a document that the reader refuses is never returned.
//   - A value from outside is bounded before it is parsed: a document or a certificate over
//     [MaxBytes], more than [MaxRoots] roots or removals, and a time outside the years 1 to 9999
//     are refused.
//   - A [Signer] is untrusted. Its certificate is read again from its DER, its signature is
//     verified with the key of that certificate before it is used, it is asked once, it gets a
//     copy of what it signs, and a panic is an error ([ErrSign]).
//   - An error returns nothing half built, wraps one of [ErrParams] and [ErrSign], and shows a
//     text from outside only with its characters outside printable ASCII escaped.
//   - Proposed points of the pages (the file mode, the order of the roots, the refusal of a list
//     whose entries have a fingerprint in part) each stand in one constant or one function, named
//     in its comment.
//
// The package opens no file, reads no clock and starts no program.
package trustset
