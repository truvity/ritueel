---
title: SSH CA key list, version 1
description: The format of the signed SSH CA key list that ritueel builds, how a key enters it, how a host reads it, the file for sshd, reason codes and test vectors.
sidebar:
  order: 7
---

*Not built yet. This is version 1 of the format that [record 0006](../decisions/0006-bundle-history-and-trust-files.md) leaves to a reference page; the code is [issue #55](https://github.com/truvity/ritueel/issues/55), in M4, and its [test vectors](/reference/ssh-ca-key-list/#test-vectors) match this page. It has the shape of the [root list](/reference/root-list/), which it follows wherever it can.*

SSH hosts trust a CA by holding its public key. The **SSH CA key list** tells a host which SSH CA keys are current: the keys of the systems that hold delegations, which keep their private halves, and the break-glass SSH CA key of each root key that keeps one, which ritueel holds offline. It carries the [trust sequence](../decisions/0006-bundle-history-and-trust-files.md) and is signed by one active root key, the X.509 root key that signs the root list, so a host that already trusts the root list needs nothing new to trust this one.

## Files

| File | Content |
|---|---|
| `ssh-ca-keys.json` | The list: one JSON object, in canonical form. |
| `ssh-ca-keys.jws` | Its signature: a detached JSON Web Signature over the bytes of `ssh-ca-keys.json`. |
| `ssh-user-ca-keys.pub` | The keys with use `user`, for sshd's `TrustedUserCAKeys` ([below](/reference/ssh-ca-key-list/#the-file-for-sshd)). |

ritueel writes the three files with the other trust files, in a numbered trust set of [the bundle](/reference/bundle/#the-layout). It writes them at every trust sequence from the first one that lists a key, so the list a host holds is always as recent as its root list. Publishing them is the holder's pipeline.

## Versioning

- `ssh-ca-keys.json` has the member `version`, an integer. This page is version `1`.
- A reader that does not know the version refuses the list with `version-unsupported`.
- A change to a member, a rule or a reason code that can turn an accepted list into a refused one, or the reverse, is a new version. The vectors are versioned with it (`testdata/ssh-ca-keys/v1/`).

## The list

`ssh-ca-keys.json` follows the JSON rules and the canonical form (RFC 8785) of the [root list](/reference/root-list/#the-list).

| Member | Required | Meaning |
|---|---|---|
| `version` | yes | `1`. |
| `sequence` | yes | The trust sequence of the ceremony that wrote it: the `sequence` of the root list written beside it. |
| `signed_at` | yes | When the list was signed: the time of the ceremony. |
| `expires_at` | yes | 13 calendar months after `signed_at`, as for the root list. |
| `keys` | yes | The SSH CA keys, in the order of their names, bytewise. The list may be empty: a ceremony that withdraws the last key must still publish a list, or hosts would go on trusting it. |

Each member of `keys`:

| Member | Required | Meaning |
|---|---|---|
| `name` | yes | The name of the delegation that the key is listed under, or `break-glass-<label>` for a root key's break-glass key. Unique in the list. |
| `use` | yes | `user` or `host`: whether the key signs certificates for users or for hosts. The break-glass keys are `user`. |
| `ssh_public_key` | yes | The key as OpenSSH writes it with no comment: `ecdsa-sha2-nistp384 <Base64>`. No key is listed twice. |
| `fingerprint` | yes | The SHA-256 fingerprint as `ssh-keygen -l` prints it: `SHA256:` and the Base64 of the digest of the key blob, with no padding. The number a person compares with the one printed at the request. |
| `root` | for a break-glass key only | The label of the root key whose break-glass key it is. Present exactly when `name` is `break-glass-<label>`. |

Version 1 lists ECDSA P-384 keys only ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 26), as the [hand-off](/reference/hand-off-contract/#ssh-ca-key) accepts only those.

An example, wrapped here for reading; the file is one line:

```json
{"expires_at":"2027-12-15T12:00:00Z",
 "keys":[{"fingerprint":"SHA256:<digest>","name":"break-glass-A","root":"A","ssh_public_key":"ecdsa-sha2-nistp384 <key>","use":"user"},
         {"fingerprint":"SHA256:<digest>","name":"example-ssh","ssh_public_key":"ecdsa-sha2-nistp384 <key>","use":"user"}],
 "sequence":7,"signed_at":"2026-11-15T12:00:00Z","version":1}
```

## How a key enters the list

- **A system's key** enters by the [hand-off](/reference/hand-off-contract/#ssh-ca-key): a request of type `ssh-ca-key` with a proof of where the key lives, answered at a ceremony. The key is listed under the name of the delegation whose wanted file has the type `ssh-ca-key` and the `use` the request asks for. An SSH CA key is withdrawn by the next list ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 29).
- **A break-glass key** is made by ritueel, in the key store of the root key it belongs to, when that key is born (the first `apply`, or an `apply` that adds a root key): a retired PIV slot recorded in the slot map for a card ([record 0003](../decisions/0003-root-cards.md)), a key of its own in the root account for a cloud root, a file for a software root ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 29). The key is listed as `break-glass-<label>`, use `user`, and leaves the list with its root key.
- **Nothing else** enters. Nobody edits the list, and no wanted file lists an SSH CA key; a delegation only declares that a key of its type may enter.

## The signature

`ssh-ca-keys.jws` is a detached JWS in compact serialisation (RFC 7515, appendix F: `<header>..<signature>`), made by the X.509 key of one active root key over the bytes of `ssh-ca-keys.json`, with the four header members of a [root list](/reference/root-list/#the-signature) signature. One signature is enough, because the list does not change the root keys. Only `typ` differs: it is `ssh-ca-keys+json`, so that a signature by the same key over the root list is not taken for this list, nor the reverse ([RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725), section 3.11).

**Who signs and when.** A root key that signs the ceremony's root list signs this list in the same ceremony, one signature, counted in the plan's touches. A ceremony that writes a new trust sequence writes both, even when no key changed; that is what makes the list expire and be renewed with the root list.

## How a host reads it

A host holds one list: the last good one, beside the root list it holds. It checks a new list in this order; the first check that fails gives the reason code, and the host keeps the list it holds.

| # | Check | Code |
|---|---|---|
| 1 | `ssh-ca-keys.jws` is a detached compact JWS whose header has exactly the members `alg`, `kid`, `x5c` and `typ`, with `alg` `ES384` and `typ` `ssh-ca-keys+json`, and `x5c` is one certificate whose `SubjectPublicKeyInfo` has the SHA-256 `kid`. | `malformed` |
| 2 | `kid` is the pin of an active root key of the root list the host holds; or, when that root list has the same `sequence` as this list, it is the pin of a root key that signed it, which may have left the list in that very ceremony. | `unknown-signer` |
| 3 | The signature verifies with the key in `x5c` over the bytes of `ssh-ca-keys.json` as read. | `signature-invalid` |
| 4 | `version` is known. | `version-unsupported` |
| 5 | The members and rules above hold: no unknown or repeated member, names unique and in order, no key twice, each key `ecdsa-sha2-nistp384` with the `fingerprint` it should have, `root` exactly on the break-glass names. | `malformed` |
| 6 | `sequence` is not lower than the `sequence` of the list the host holds. | `rollback` |
| 7 | When `sequence` equals the held list's, `ssh-ca-keys.json` is byte for byte the held one. | `sequence-conflict` |
| 8 | The host's clock is before `expires_at`. | `expired` |

A host takes a new root list **before** the SSH CA key list of the same sequence, so that check 2 reads the root keys of that sequence; a list signed by a root key the host's root list does not yet show is `unknown-signer`, and the host tries again after it has updated the root list. A host that holds no root list uses its initial pins for check 2, as for the root list. The host verifies the bytes it received and does not re-serialise them. When every check passes, the new list replaces the one it holds, and the keys of the old list that are not on the new one are no longer trusted. Receiving the current list again is not an error.

**When the list a host holds expires** and no newer one has arrived, it keeps the list, goes on trusting its keys, and raises a warning, as for the root list ([record 0006](../decisions/0006-bundle-history-and-trust-files.md)). `ritueel verify ssh-ca-keys` reports it as the warning `held-expired` in the member `warnings` of its JSON output and prints it on standard error; the exit code does not change ([the output](/reference/cli/#machine-readable-output)). `status` warns 60, 30 and 14 days before the newest list expires.

These codes belong to the host and are not sent anywhere.

## The file for sshd

`ssh-user-ca-keys.pub` is text, with LF line endings:

1. The first line is `# trust-sequence: <sequence>`.
2. Then the `ssh_public_key` of every entry with use `user`, one to a line, in the order of the list.
3. Nothing else.

It is the file sshd reads as `TrustedUserCAKeys`; a line that begins with `#` is a comment there. It is deterministic, and it is not signed: a host that holds the list checks the file against it (`user-keys-mismatch`) before it installs it. A host key list for `known_hosts` is not derived, because a `@cert-authority` line names the hosts it applies to, and ritueel does not know them; the entries with use `host` are in the list for the system that does.

**The command.** `ritueel verify ssh-ca-keys FILE (--held FILE | --root-list FILE) [--user-keys FILE]` runs the host's checks on the list `FILE` (its `ssh-ca-keys.json`; the signature is the `.jws` beside it) against the list the host holds, with the root keys of the root list it holds (`--root-list FILE`, checked as `ritueel verify root-list` checks it; the root keys that signed it are in the `.jws` beside it, which check 2 reads when the sequences are equal). `--user-keys FILE` also checks the file for sshd. It signs and writes nothing, and exits 0 when the list is accepted and 3 with the code when it is refused ([Commands](/reference/cli/#commands-for-the-trust-files-that-come-later)).

## Test vectors

The vectors are in [`testdata/ssh-ca-keys/v1/`](https://github.com/truvity/ritueel/tree/main/testdata/ssh-ca-keys/v1). They are public material only, made by the same run of [`generate.py`](https://github.com/truvity/ritueel/blob/main/testdata/hand-off/generate.py) as the hand-off vectors, so the root keys are the same test root keys: A and B are active, Z is on no list, and the list `seq7-a` is the list of trust sequence 7, which the hand-off answers of type `ssh-ca-key` name.

- `manifest.json` names each root key with its pin, every list with its signer, the two `ssh-user-ca-keys` files and every case.
- A case gives the list the host holds (`held`, or `null`), the list it receives (`candidate`), the root list the host holds (`root_list`: the labels of its active root keys, and when its sequence is the candidate's, that sequence and the label of a root key that signed it), the clock if it is not the manifest's `2026-11-15T12:00:00Z`, and the expected outcome: `accept`, `refuse` with a reason code, or `warn` with a warning. A case with `user_keys` also checks that file against the candidate.
- The keys are made-up throw-away keys, and the break-glass keys are A's and B's.

| Group | Cases |
|---|---|
| Accepted | A first list; an update; the same list signed by the other root key; a list that removes a revoked root key's break-glass key, signed by the surviving root key; the same, signed by the retiring root key in the ceremony that removes it; a list with no key left; the same list again; the file for sshd. |
| Refused | A lower sequence (`rollback`); another list at the same sequence (`sequence-conflict`); a list signed by a root key that left the list in an earlier ceremony, and one signed by Z (`unknown-signer`); a list changed after signing (`signature-invalid`); an expired list (`expired`); version 2 (`version-unsupported`); an unknown member, a key listed twice, a list signed with the root list's `typ` (`malformed`); a file for sshd that holds a host key (`user-keys-mismatch`). |
| Warned | The held list expired and no newer one came. |

CI checks that the manifest names every file of the set, that the pins match the root files, that every list's signature verifies except the one a case expects to fail, that every other list follows the rules above, and that each file for sshd holds the user keys of its list (`just check-vectors`). The requests of type `ssh-ca-key` are in [the hand-off vectors](/reference/hand-off-contract/#test-vectors).

## Choices made

| Choice | Chosen | Other options | Why |
|---|---|---|---|
| One list or two | One list with a `use` for each key. | One list for user CAs and one for host CAs. | One signature, one expiry and one sequence to follow. The two kinds differ in what a host does with them, and the `use` member is where it learns that. |
| `use` | In the list, from the request. | A key may do both; a host decides. | A user CA key trusted as a host CA lets whoever holds it vouch for hosts, and the reverse. Keeping the two apart costs one key more for a system that wants both. |
| The signer's key | An X.509 root key that signs the root list. | A key of its own for the list. | The audience, lifetime and revocation are those of the root list ([record 0006](../decisions/0006-bundle-history-and-trust-files.md)). A third key would cost a slot and a touch. |
| Which root keys check 2 reads | The root list the host holds, with the one exception of a signer of the root list of the same sequence. | Only the held root list; any root key of the new root list. | A retiring root key signs the ceremony that removes it, so a strict rule would refuse the list of that very ceremony. Reading the new root list would let a list vouch for its own signer. |
| Break-glass key in the list | Listed like any other key, by name. | A separate file; not published, kept by the holder. | Hosts need it to accept an emergency login, and one list is one place to look. The key leaves with its root key. |
| A file for sshd | Derived, with the sequence in a comment, and checked against the list. | Only the JSON; a `known_hosts` file as well. | `TrustedUserCAKeys` is the file sshd reads, and a comment line is allowed in it. A `known_hosts` line needs host patterns that only the consumer knows. |
| Key type | `ecdsa-sha2-nistp384` only. | Ed25519 as well. | BSI, the German federal office for information security, lists only ECDSA for SSH signatures (TR-02102-4, 2026-01); a host in FIPS mode refuses Ed25519 (Red Hat documentation); and one algorithm is one code path, as for the rest of the contract. |
| Empty list | Allowed, and written once any key has been listed. | The list vanishes with its last key. | A host that is not told its last key is withdrawn would go on trusting it. |

## Follow-ups

- The code: writing, signing and reading the list and the file for sshd, with the host rules, and a test that the same inputs give the same bytes ([issue #55](https://github.com/truvity/ritueel/issues/55)).
- The break-glass key in each key store: the retired slot of the slot map, the cloud root account's key and the file of a software root ([issue #55](https://github.com/truvity/ritueel/issues/55)).

## Standards

| Standard | Used for |
|---|---|
| [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515), [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) | The detached JWS and `ES384`, as for the root list. |
| [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725) | Explicit typing with `typ`. |
| [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) | The canonical form of `ssh-ca-keys.json`. |
| [RFC 5656](https://datatracker.ietf.org/doc/html/rfc5656) | `ecdsa-sha2-nistp384` keys. |
| OpenSSH `sshd_config` (`TrustedUserCAKeys`) and `PROTOCOL.certkeys` | What a host does with a user CA key, and what a CA key signs. |
