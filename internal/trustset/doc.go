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
// folder name of a trust set; [Draft.SetName] and [Set.Name] give it for the SHA-256 of root-list.json. [FileNames], [FileMode] and the limits are in layout.go, the one
// place that names the files. The writer of the general JWS of root-list.jws is in jws.go and is
// reached through [Draft.Sign].
//
// A trust set is made in three steps. [NewDraft] takes an [Input] (the new entries, their current
// certificates, the previous list and every earlier list of the bundle in the order of the hash
// chain, and how each root key that leaves leaves) and checks everything that needs no key: the
// kind of change ([Kind]: first, renewal, add, retire or revoke, and nothing else), who signs it
// (who.go, list page "Who signs"), that no root key that left comes back ([ErrReturns], reason
// code [CodeRootReturns], record 0006, rule 54), that no label is reused, that every stored removal
// authorisation is valid, and that the list and the CA bundle are accepted by the reader of the
// page. It returns a [Draft] with the bytes of root-list.json and ca-bundle.pem, which depend on no
// signature, so a plan can name their digests before a key is touched. [Draft.Sign] checks the
// signers against the draft before it asks any key ([ErrSigners]), asks each signer once in label
// order, verifies each signature before the next signer is asked, reports each one to the caller
// ([Signed]), and then asks the reader of the page about its own output ([ErrSelf]). It returns a
// [Set], the three files whole and checked, and [Set.Write] writes it with one call of fsx.
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
//   - An error returns nothing half built, wraps one of [ErrParams], [ErrSign], [ErrSigners], [ErrReturns] and [ErrSelf], and shows a
//     text from outside only with its characters outside printable ASCII escaped.
//   - Proposed points of the pages (the file mode, the order of the roots, the refusal of a list
//     whose entries have a fingerprint in part, the refusal of a reused label, the refusal of a
//     signing time before the previous one, the refusal of a list that adds and removes keys at
//     once) each stand in one constant or one function, named in its comment.
//   - The builder does not order the earlier lists and reads no name for an order: the caller
//     gives them in the order of the hash chain, and the builder counts them.
//
// The package opens no path itself (Set.Write goes through package fsx), reads no clock and starts
// no program.
package trustset
