// Package pki builds the bytes of the X.509 certificates of a bundle: the root certificate and
// the intermediate certificate, from a profile written in docs/reference/bundle.md ("The root
// certificate") and docs/reference/hand-off-contract.md ("What is issued"). Record 0007, rule 15,
// has every ceremony that signs with a root key issue its root certificate again; record 0006,
// rule 16, defines the pin of a key, which [SPKISHA256] computes.
//
// The package builds, signs through a [crypto.Signer] and assembles; it never holds a key. [RootTBS]
// and [IntermediateTBS] return the DER of a TBSCertificate (RFC 5280, section 4.1.1.1), which is
// what a key signs. [SignRoot] and [SignIntermediate] sign it through a signer, so a card or a cloud
// key plugs in where a software key does (record 0003, rule 19; record 0004, rule 12; record 0010,
// rule 20), and [Assemble] puts the signature to it. The steps are separate so that a plan can name
// the exact bytes before any key signs them ([TBSSHA256]).
//
// A key signs only the body of the parameters it is given. [SignRoot] and [SignIntermediate] take
// the parameters of the builders (for an intermediate, the request as DER with them) and the body,
// build the body again, and sign only when it is the same bytes; they also refuse a signer whose key
// is not the key of the parameters, before the key is used, so that a card is not touched for a body
// that is not the one that was shown, or for a key that does not issue it. There is no function that
// signs a body alone. [Assemble] reads a body and a signature and verifies one against the other
// with the issuer's key; it checks that the body is of the form the builders write, and it cannot
// know that a request stands behind it, because it has none. Every refusal comes before a key is
// used.
//
// A key is ECDSA on P-384 and a signature is ecdsa-with-SHA384 (record 0002, rule 14). Every
// time is in whole seconds and in UTC; nothing is rounded: a time with a fraction is an error.
// Every output is deterministic: the same parameters give the same bytes.
//
// An intermediate is issued exactly as the request asks, or not at all: the builder copies the
// subject, the public key, the key usage, the name constraints and the extended key usage as
// the request has them (the extension values byte for byte), and refuses a request that holds
// anything else. A request is read once, by [ParseRequest] (or [ParseRequestFile] for a file), from
// its own bytes; the view that it returns is exactly what will be issued, and the policy is run on
// it. [IntermediateTBS] reads the same bytes by the same function and adds only what needs the
// issuer. It does not decide what a policy allows; the policy refuses first.
//
// An error that this package makes wraps one of four kinds, and one only: [ErrParams] (a parameter of
// the caller is wrong), [ErrRequest] (the request asks for something that is not issued), [ErrSignature]
// (a signature does not verify or is not a DER ECDSA value) or [ErrPEM] (a PEM file is not in the form of
// the page; it is a fault of the file and not of a request, and only [ReadPEMFile] returns it). The
// error of a signer is the signer's: it stays reachable with errors.Is and errors.As under an
// [ErrSignature], and it may itself wrap another kind or any other error. The text of an error is printable ASCII: it holds only fixed
// words and numbers, and any text that came from a parser is shown by [jsonset.Escape].
//
// Every exported function copies what it reads more than once (the serial, the keys, the bytes of the
// request, of the issuer name and of the body) at the top of its call and works on the copies, and it
// asks a signer for its public key once and copies it. So a change that the caller makes to its
// parameters after the call has started has no effect, and one call never builds a body from two
// values of one parameter. A write by the caller while the copy is taken is the caller's own data
// race and is reported by the race detector as the caller's; the package takes each copy twice and
// refuses the call with an [ErrParams] when the two differ, which catches a write that overlaps the
// copy, but it cannot make a copy atomic against a writer, so it cannot promise to catch every one.
//
// A refusal of a request also says which check of the hand-off contract it is: pki.CheckOf(err) returns
// the [Check] (malformed, algorithm-unsupported, possession-invalid or policy), and its Code method
// the reason code as the contract writes it. The error is still one [ErrRequest] and no other kind.
//
// # What the caller must do
//
// The package checks what it can see in its parameters. These things it cannot see, so the code
// that runs a ceremony does them. The list is what is known at this time and is not a promise that
// nothing else is left:
//
// Do not change the parameters, or the objects they point to (a serial, a key, a slice of bytes, the
// signer), while a call runs. The package copies them at the top of the call, so a change after that
// has no effect; a change while it copies is a data race of the caller's own code. Use one signer
// object for one call, or a signer whose Public does not write to shared state.
//
// Show the digest of the body that is signed, and sign with the same parameters. Build the body with
// [RootTBS] or [IntermediateTBS], show [TBSSHA256] of it to the person at the ceremony, and give the
// signing function the same parameters, the same request bytes and the same serial. The signing
// function builds the body again and refuses any other; it cannot know which digest the person saw.
// Do not make a new serial or take a new ceremony time between showing and signing. The signature
// that is returned is over the package's own body, which is the body that was shown; give [Assemble]
// that same body, and that signature, and the key that signed.
//
// Make a serial from [NewSerial] with a nil reader, and keep every serial issued per issuer in
// the record of the ceremony, refusing one that was issued before. The package does not remember
// serials, and cannot tell a bad source of random numbers from chance.
//
// Pass the subject of the root certificate that will be presented, exactly as that certificate has
// it (its RawSubject), as IssuerSubject, and the key that will sign as IssuerKey. The signing
// functions check the key; nothing here can know that the subject is the name in the certificate
// that a relying party will hold, and a body that names another issuer than the certificate of the key
// chains to nothing.
//
// Keep the certificate inside the root's life. A certificate may not outlive the root certificate
// that issues it: check that the notAfter of an intermediate (the ceremony time and
// [IntermediateValidityMonths] months) is not later than the notAfter of the root certificate, and
// that the ceremony time is not earlier than its notBefore. Take the ceremony time from a clock that
// the ceremony trusts, in whole seconds, and check it against the real time: the package takes the
// ceremony time as given and cannot know that it is the day of the ceremony. (The package refuses a
// ceremony time that would end a validity on 9999-12-31 23:59:59Z, and has the number of months of
// the profile as a constant.)
//
// Run the policy on the request that is issued. Read the request once with [ParseRequest] or
// [ParseRequestFile], apply the policy to the view it gives (the subject through
// [Request.SubjectName], the key, the extensions, [Request.NameConstraints]), hash [Request.DER] for
// the request_sha256 of the hand-off contract, and give the same bytes to [IntermediateTBS] and to
// [SignIntermediate]. The package refuses only the smallest set of names (see IntermediateTBS), so
// the policy still holds the requester to the subjects it may ask for, compares the name
// constraints with the requester's zones label by label and never as a suffix of a string (a short
// base is a suffix of everything), and decides which subjects a requester may ask for. The subject is
// printable ASCII in version 1 (a rule of the contract that this package holds), so it holds no letter
// of another script, no invisible character and no space but U+0020. ASCII still has letters that look
// alike (0 and O, 1 and l and I), and characters that a display may read as structure (a slash, a
// comma, a quote, a dollar sign), so the person at the ceremony and the policy see the subject, and
// whatever shows it escapes it.
//
// Make the contract's checks of the key store and of the evidence (checks 6 to 8 of "What the
// certifier checks": the store the policy allows, the attestation or the key state, and that the key
// in the evidence is the key of the request). This package makes none of them. [ParseRequest] runs
// the content rules, which the contract counts in its check 9, in front of them, so a request that has
// a fault of content and a fault of the store is refused for its content by ParseRequest alone. To keep
// the contract's order, call [RequestKey] (or [RequestKeyFile]) first: it makes checks 2, 4 and 5 and
// returns the key of the request, or the refusal of one of them; run checks 6 to 8 with that key (it is
// good for nothing else, and says nothing about what the request asks for); then call [ParseRequest]
// and report its refusal, which is the policy, after them.
//
// Give the same bytes to [RequestKey], to [ParseRequest] and to [IntermediateTBS] and
// [SignIntermediate], and compare [Request.PublicKey] with the key that [RequestKey] returned before
// you use the result of checks 6 to 8. Each call reads only the bytes it is given and knows no other.
// If the calls are given two different requests (a file that is read twice and changes between the
// reads, or two slices that are not equal), the checks of the store, of the evidence and of the key
// match run on the key of the first, and a certificate is issued for the key of the second. Read the
// file once and give that one slice to [RequestKeyFile] and to [ParseRequestFile]; give the builders
// the DER of [Request.DER], which is the request that was read (for a request that is not a file, give
// the one slice of DER to every call).
//
// Keep the roots of a bundle apart. Give [IntermediateParams] the list of every root of the bundle
// ([RootRef]: its subject and its key; the issuer is one of them): [IntermediateTBS] and
// [SignIntermediate] then refuse a request for the key of any root, or for a subject that is the name
// of any root as OpenSSL compares names. The package cannot know the bundle, so the list is the
// caller's to build from it, whole. The package refuses a list in which two roots have one name (as
// [SameName] compares) and two keys, or one key and two names; a root that is listed twice, with the
// same bytes of its subject and the same key, is accepted once (the second entry adds no name and no
// key, so it opens no second path). The refusal is an [ErrParams], for every call, because an OpenSSL
// folder of certificates holds one file for a name, and a chain is built by name.
//
// Limit the touch of a card. The signing functions take no context, and a signer that waits for a
// person waits until the person acts. Run them so that the ceremony can stop waiting and say that
// nothing was signed.
//
// Print the text of the top error and no other. An error may hold the error of a signer or of a
// parser as its cause; the text of the top error shows it escaped, and the cause itself may carry
// bytes that came from outside.
package pki
