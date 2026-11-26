// Package software is ritueel's own software key store, the `file` backend: key files with plain
// or passphrase-encrypted content. No ceremony calls it any more. A test root's keys are made and
// used through the key port of atom (record 0012, rules 1 and 2; internal/keystore/port and
// internal/keystore/atoomsoftware), and the key directory is judged by internal/keydir. What still
// uses this package is the in-memory key ([Generate], [Key]) that tests of internal/trustset,
// internal/openpgp and internal/ceremony sign with, and what the exception of record 0012, rule 4,
// keeps for a person's own key: the encrypted key file, whose home this package is until that work
// moves it. It is not to be wired into a new caller; the rest of it is removed when the records
// that describe it are rewritten.
//
// What follows describes the package as built.
//
// The software key store, the `file` backend (docs/reference/software-store.md;
// record 0002, rules 9 to 11): a key is made in memory (record 0002, rule 4), written straight to
// a key file in a key directory outside the bundle (record 0005, rule 30), and opened again at a
// later ceremony.
//
// Two modes are built. [ModeTest] is the TEST ONLY mode: plain key files, marked as such, for a
// test root (record 0005, rule 26). [ModePassphrase] is the passphrase mode: an age file with one
// scrypt recipient (record 0002, rules 20, 22 and 28), for a root that is not a test root and a
// holder without cards, and for a script root (record 0005, rule 27). The way that is the default,
// a passkey on each root card with a recovery key (record 0002, rules 19 to 21), is not built: its
// format is not written before the proof on a card, and there is no Mode for it. A caller that has
// neither a test root nor a source of passphrases must refuse with [ErrNotBuilt] and a sentence
// that says so.
//
// The package is a library. It has no command and no flag; the commands that make and use a root
// call it. It writes no log line, prints nothing, reads no environment variable, starts no
// program and makes no network call.
//
// # The key directory
//
// [CheckKeyDir] refuses a key directory that is the bundle, inside it, or inside the work tree of
// any repository that encloses the bundle, so a copy of a bundle cannot carry a root; the rules
// are those of internal/keydir, which belong to no key store. [Open]
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
// # Passphrase files
//
// A passphrase file is an age file of the format age-encryption.org/v1, binary and not armoured,
// made by the library filippo.io/age (only its package age). It has one scrypt recipient and no
// other stanza, and its payload is the PEM of the X.509 key, the binary transferable secret key,
// one signature packet or the text of a JWS. The work factor that is written is [WriteWorkFactor]
// (2^18); a file is read at any work factor from [MinWorkFactor] to [MaxWorkFactor] (2^18 to
// 2^22).
//
// The header is looked at before any work. A file is refused as an [ErrKeyFile], before scrypt
// runs and before a passphrase is asked, unless its header holds exactly one stanza of the type
// scrypt, with two arguments (a salt of 16 bytes in unpadded Base64 and a work factor written as a
// plain decimal number from 18 to 22) and a body of 32 bytes. A header that asks for 2^30 costs
// nothing. The library's own identity then runs with its maximum work factor set to 22, the
// payload is read up to [MaxKeyFileSize] and one byte more, and a longer payload is refused. A
// file that did not open with the passphrase is an [ErrWrongPassphrase]; a damaged or cut file is
// an [ErrKeyFile]. No text of the library is repeated in an error, because it holds lines of the
// file.
//
// A passphrase comes from a [PassphraseSource], once for each key that a call saves or opens, and
// is never kept. [CheckPassphrase] holds it to the rule of record 0002 (at least 15 characters,
// valid text, no control or format character); it judges neither randomness nor strength, so
// "generated and not chosen" is advice and not a check. [ReaderSource] reads one line for each
// ask from a reader that the caller owns, for example a descriptor given as --passphrase-fd. The
// package asks no terminal. A save writes the file, reads it back and opens it again with the same
// passphrase, so a save of a passphrase file runs scrypt twice.
//
// A [Purpose] has a [Role]. The zero value, [KeyFile], is the passphrase of a key file that a call
// opens, and [Choose] the new passphrase of one that it writes; both are held to [CheckPassphrase].
// [Import] is the passphrase of a file that an OpenPGP program exported: it was chosen under that
// program's rules, so it is held only to [CheckPassphraseFor] (not empty, at most
// [openpgp.MaxForeignPassphraseBytes]), and [ReaderSource] reads a line of that length for it.
//
// # Adopted keys
//
// A person's existing OpenPGP primary (RSA-4096, EdDSA on Ed25519 or ECDSA on P-384; record 0008,
// rules 5 and 6) is kept in the same file name as a key that ritueel made, `<label>.openpgp.key.age`,
// with another payload: the lone secret key packet that [openpgp.ForeignKey.SecretPacket] writes
// and [openpgp.OpenSecretPacket] reads, with no user ID. The two readers tell the forms apart, and
// each refuses the other with an [ErrKeyFile] that says which form it found. [Store.SaveAdopted]
// writes it, only in the passphrase mode (the key of a person is never written without encryption);
// it asks the source for the passphrase of the exported file only when that is protected, and then
// for the new passphrase. [Store.OpenAdopted] and [Store.CheckAdopted] compare the fingerprint, the
// creation time and the public part of the key in the file with an [Expect], before any signer is
// returned. An [AdoptedKey] is a crypto.Signer that delegates to the signer of internal/openpgp,
// guards its options, and verifies every signature with its public key. It is not a keystore.Key,
// whose contract is P-384 with SHA-384. The store does not judge the history of the key (revoked,
// expired, revoked by another key): the ceremony of the adoption does. The payload of an RSA-4096 key
// is at most 1822 bytes against the cap of [MaxKeyFileSize].
//
// What an open costs depends on the work factor that the file says, and a file may say any factor
// from 18 to 22. At 18 an open needs about 256 MiB of memory and about a second. At 22, the
// highest, it needs about 4 GiB of memory and 7 to 9 seconds (measured), and it needs them at every
// open: also for a wrong passphrase and for a file whose payload is damaged, because only the work
// shows that. The header is looked at first, so a factor above 22 costs nothing, but one file that
// says 22 can still cost a small machine its memory.
//
// # Secrets in memory
//
// Go does not promise that a secret that was in memory is cleared. The package clears the byte
// buffers that it made (and that internal/openpgp made for it), the numbers of the private keys
// that it parsed itself, the passphrase slices that a source gave it, the lone secret key packet that
// [Store.SaveAdopted] made, and the scalar of a [Key] and the numbers of an [AdoptedKey] when it is
// closed (through [openpgp.ForeignSecret.Wipe]), and no more. The age library takes a passphrase as
// a string and keeps a copy of its own: those two copies cannot be cleared from here, and the
// passphrase of an exported file is read by internal/openpgp from the slice that this package
// clears after the call. The plain key also passes through
// buffers of the age library (the chunks of its stream, 64 KiB each, which hold the payload as it
// is written or read), and this package cannot clear those either. Out of its
// reach are the copies inside crypto/rsa, crypto/ed25519 and crypto/ecdsa (the key keeps its scalar in its own memory, and a
// slice that Bytes returned is that memory), the copies that crypto/x509, encoding/asn1,
// encoding/pem and the OpenPGP reader of go-crypto made while they read the key, and the copies
// that the garbage collector moved. The pages that the system swapped out are out of its reach
// too. A scan of the memory of a process after Close can still find the scalar. A key and a passphrase are never put into an error, a
// file name, a log line or a temporary file other than the key file itself.
package software
