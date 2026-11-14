// Package software is the software key store, the `file` backend (docs/reference/software-store.md;
// record 0002, rules 9 to 11): a key is made in memory (record 0002, rule 4), written straight to
// a key file in a key directory outside the bundle (record 0005, rule 30), and opened again at a
// later ceremony.
//
// What is built is the TEST ONLY mode: plain key files, marked as such, for a test root (record
// 0005, rule 26). The mode of passphrase files is named ([ModePassphrase]) and refused with
// [ErrNotBuilt]. The way that is the default, a passkey on each root card with a recovery key
// (record 0002, rules 19 to 21), is not built either: its format is not written before the proof
// on a card, and there is no Mode for it. A caller that has neither a test root nor a source of
// passphrases gets a refusal that says so.
//
// The package is a library. It has no command and no flag; the commands that make and use a root
// call it. It writes no log line, prints nothing, reads no environment variable, starts no
// program and makes no network call.
//
// # The key directory
//
// [CheckKeyDir] refuses a key directory that is the bundle, inside it, or inside the work tree of
// any repository that encloses the bundle, so a copy of a bundle cannot carry a root. [Open]
// resolves the links of the path as the system does, in order and without cleaning the text first,
// checks that, and opens the folder that was checked with internal/fsx, which follows no link at
// the last element; then it resolves and checks the path again, and refuses when the folder is no
// longer the one that was checked. Every file is read and written through fsx. A link that is put
// into a parent and taken out again between the two looks cannot be seen: that is the holder's
// folder, as is the mode. The mode
// of the folder is not checked or changed: on exFAT a mode means nothing, so the mode 0600 of a
// file protects nothing there, and a TEST ONLY file on a stick can be read by anyone who holds the
// stick. A mode of 0700 for the folder is the holder's duty.
//
// # Writing and reading
//
// A file is written by the writer of internal/fsx: a temporary name in the same folder, created
// exclusively with the mode 0600 from the start, flushed, renamed to its final name by a rename
// that refuses to replace, and the folder flushed (record 0006, rules 31 to 33). A file that exists
// is never replaced: the name is looked at before a byte of the key is written, so a name that is
// taken leaves nothing behind. The first write error stops the store's writer and is not retried.
// A cut during a write leaves what the file system leaves; the package does not claim to cure the
// faults of a removable stick (issue 181). A write that fails after the temporary file was made
// leaves that file, which holds the whole key or a part of it: nothing is deleted, and the error
// names the temporary file so that the caller can tell the person to remove it. A save is write,
// read back, check: only then is [Key.Saved] true, and a file that was written stays where it is
// when a later step fails (nothing is deleted).
//
// A read accepts what the page describes and nothing else: one PEM block, one marker line, one
// armour block with one header, the packets of one certificate and no trailing byte. The size of a
// file is checked against [MaxKeyFileSize] before anything is parsed; internal/fsx offers no lower
// limit for a read, so a file is read whole up to its own limit of 8 MiB first, and a longer one
// is refused by fsx (the buffer is cleared). A key that was opened must
// be compared by the caller with the pin or the fingerprint in the trust set before it signs: the
// package cannot know them, and it cannot tell a copy of an older key file from the file.
//
// # Secrets in memory
//
// Go does not promise that a secret that was in memory is cleared. The package clears the byte
// buffers that it made (and that internal/openpgp made for it), the numbers of the private keys
// that it parsed itself, and the scalar of a [Key] when it is closed, and no more. Out of its
// reach are the copies inside crypto/ecdsa (the key keeps its scalar in its own memory, and a
// slice that Bytes returned is that memory), the copies that crypto/x509, encoding/asn1,
// encoding/pem and the OpenPGP reader of go-crypto made while they read the key, and the copies
// that the garbage collector moved. The pages that the system swapped out are out of its reach
// too. A scan of the memory of a process after Close can still find the scalar. A key and a passphrase are never put into an error, a
// file name, a log line or a temporary file other than the key file itself.
package software
