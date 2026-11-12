---
title: Root transitions, version 1
description: The states of a root, root add, retire and revoke with their checks, the cross-certificate and the OpenPGP vouch, and what each state does to trust files.
sidebar:
  order: 11
---

*Not built yet. This is the page that [record 0007](../decisions/0007-changing-and-losing-a-root.md) leaves for the rules and profiles; the code is [issue #13](https://github.com/truvity/ritueel/issues/13), in M4. The ideas are taught in [Moving from one root to another](/learn/transitions/). The commands, words and file names on this page are from before the decisions of 2026-11-12; the design is at https://ritueel.id/design/.*

A transition moves trust from one root key to another without breaking a client that has not learned of the change. It never moves a key: the new root key is born in its store, and an active root key vouches for it ([principle 1](/principles/)).

## The state of a root

| State | Meaning | Set by |
|---|---|---|
| `active` | On the root list. It signs, its certificate is in the CA bundle, its primary is in the keyring package, it signs its CRL, and its break-glass key is on the SSH CA key list. | The first `apply`; an `apply` for an added key |
| `retired` | Ended in good order. It is in none of those trust files. What it certified is still certified by another active root key. | An `apply` once the wanted retirement date is reached |
| `revoked` | Ended by loss, theft or compromise. As retired, and its revocation signature is published beside the keyring. | `revoke` |

There is no state for the overlap. **An overlap is the time in which a root key and the root key that replaces it are both `active`.** The wanted root file says what the new key replaces and until when ([below](/reference/transitions/#in-rootjson)).

## The target

The number of active root keys the holder wants is the **target**: the number of keys in the wanted root file (the first `apply` makes 2 keys for two cards and 1 for a cloud root). It is not stored. `status` compares it with the number of active root keys:

| Active root keys | Finding | Level |
|---|---|---|
| Fewer than the target | `root-set`: the set is short, so it names the root keys that are missing. | alert (11) |
| More than the target, until the overlap ends | `root-overlap`: the date the overlap ends, and the root keys involved. | notice (10) |
| More than the target, after that date | `root-overlap`: the overlap is overdue. | alert (11) |

A key added with no key to replace grows the set, and a retirement with no replacement shrinks it. Neither is done by accident: the target is the number of keys in the wanted root file.

## The commands

An X.509 root key is not renamed: its name is inside the certificate and every intermediate names it as issuer. A new name is a new key: add it to the wanted root file, overlap it, then retire the old key ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 28).

| Change | What you do | Needs | Writes |
|---|---|---|---|
| Add a root key | Write the key in the wanted root file. To replace a key, name it and give the day the overlap ends. Then run `ritueel apply`. | The card, or the KMS roles, of the new key, and the card or role of every active root key. A root key that cannot come is revoked first. | The new root key; its vouches; the next trust files. |
| Retire a root key | Write the retirement date in the wanted root file. Then run `ritueel apply`. | The card or role of every active root key, the retired key included. | A ceremony record, and the next trust files without the key. |
| Revoke a root key | Run `ritueel revoke KEY...` ([Commands](/reference/cli/)). | The card or role of every other active root key, the stored revocation signature, and the stored removal authorisation of the key unless it signs. | The next trust files without the key. |

Changing the root keys requires every current root key, or a root key's stored removal authorisation ([the root list](/reference/root-list/#who-signs)). When a key is added or retired, each root key signs the new root list in the same ceremony, with a touch on a card, and the plan counts them. With two cards, adding and retiring a root key are two-card ceremonies; the yearly ceremony stays a one-card ceremony, because its list has the same root keys. `revoke` is no ceremony and reads no plan: the other root keys sign the new root list, which carries the removal authorisation of the revoked key ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rules 8 and 9).

The end of the overlap is a wanted end date, a day in UTC, with no default: how long the overlap must last is the time that the slowest client you care about needs, and only the holder knows it ([Moving from one root to another](/learn/transitions/)). The vouching root key is the key on the card of the year unless the holder names another card, with the reason recorded, as for every ceremony.

### Adding a root key

Refused with `root-absent` unless every active root key can sign the next root list.

1. The plan names the births ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md)): the new root's X.509 root key, OpenPGP primary and break-glass SSH CA key, with their revocation signatures and the removal authorisation ([Revocation material](/reference/revocation-material/)).
2. The new root's own certificate, self-signature and CRL are signed by the new keys.
3. The vouching root key signs the cross-certificate and the OpenPGP certification below, with a touch each on a card (a cloud root key signs on the typed digest and the role session), and the new fingerprints have been shown before the signature.
4. Every active root key and the new root key sign the next root list, which holds them all; the vouching root key signs the next CRL; the CA bundle, the SSH CA key list and the keyring are built with the new root key.

### Retiring a root key

The plan leaves the retirement out, with the reason, unless all of these hold:

| Check | Code |
|---|---|
| At least one other root key stays active. | `last-root` |
| Every active root key, the key to retire included, can sign the next root list. A root key that cannot is revoked instead. | `root-absent` |
| The root key is replaced by an active root key (named in the wanted root file), or the holder has said that the set gets smaller. | `target-required` |
| The overlap has ended (the wanted end date has passed). A key is retired earlier only when the holder moves the date and records a reason. | `overlap-open` |
| Nothing depends on this root key alone: every declared delegation has a certificate, or a binding, from another active root key over the same key, valid for at least 30 more days. | `still-needed` |

`still-needed` lists what is missing. The fix is the next `apply`, with a fresh request for each delegation over its same key, which an OpenPGP subkey also needs when a new primary joined after the subkey's request ([the contract](/reference/hand-off-contract/#the-request-1): a request back-signs for every active primary). The retired root key's certificate is no longer in the CA bundle, its CRL is no longer written, and its primary leaves the keyring package.

### Revoking a root key

It never waits for anything but the stored revocation material, because it is the emergency exit.

| Check | Code |
|---|---|
| At least one other root key stays active, and it can sign. | `last-root` |
| Every other active root key can sign the next root list. | `root-absent` |
| The file's digest equals the digest the bundle holds for this root key and reason, and its signature verifies over the root key's primary. | `revocation-mismatch`, `revocation-invalid` |
| Unless the root key signs the new list itself, its stored removal authorisation has the digest the bundle holds and a signature that verifies over its pin ([revocation material](/reference/revocation-material/#the-removal-authorisation)). | `revocation-mismatch`, `revocation-invalid` |

It then writes a root list without the root key, signed by the other root keys and carrying its removal authorisation, a CA bundle, a keyring and an SSH CA key list without it, and stops writing the root key's CRL. The revocation signature stays with the holder, outside the bundle, and is published beside the keyring package, not in it ([record 0009](../decisions/0009-release-keys-and-the-keyring.md), rule 17). What the root key alone had certified is **not** re-certified here: `status` reports each such intermediate as critical until a ceremony certifies it again, over the same keys ([A lost root card](/guides/lost-root-card/)).

## The vouch

Both vouches are signed by the vouching root key, at the ceremony that adds the key, and are published in `vouches/` of the trust set. They are not trust anchors and are in no CA bundle.

### The X.509 cross-certificate

`vouches/x509-<new>-by-<signer>.pem`, one certificate in PEM (RFC 7468).

| Field | Value |
|---|---|
| Version, serial | 3. A positive number of at most 20 bytes with at least 64 random bits. |
| Signature | `ecdsa-with-SHA384`, by the vouching root key. |
| Issuer | The subject of the vouching root key's current certificate. |
| Subject | The subject of the new root key's certificate. |
| Subject public key | The new root key's public key. |
| Validity | `notBefore` is the ceremony time. `notAfter` is 13 calendar months later, as for an intermediate. It is made again by each yearly ceremony while the overlap lasts. |
| Basic constraints | Critical. `cA` true, no path length. |
| Key usage | Critical. `keyCertSign` and `cRLSign`. |
| Subject key identifier | The new key's, as in the [root certificate profile](/reference/bundle/#the-root-certificate). |
| Authority key identifier | The vouching root key's subject key identifier. |
| Name constraints | Absent: constraints belong to the intermediates. |
| Anything else | Absent: no CRL distribution point, no authority information access. |

A client that trusts only the old root key can build a path from an intermediate that the new root key issued: intermediate, then this certificate, then the old root key. A client that has the new CA bundle needs it not at all.

### The OpenPGP certification

`vouches/openpgp-<new>-by-<signer>.pgp`, binary: the new primary's public key packet, its user ID, and one certification (RFC 9580, section 5.2.1.4, type `0x10`) made by the vouching primary over them. Its hashed area holds the signature creation time (the ceremony time), a signature expiration time of 13 calendar months, and the issuer fingerprint; its unhashed area holds the issuer key ID ([the packet rule](/reference/hand-off-contract/#issuer-key-id)). The hash is SHA-384.

It is **not in the keyring package**: that package holds only the primaries' own packets ([record 0009](../decisions/0009-release-keys-and-the-keyring.md), [the keyring page](/reference/keyring-package/#what-the-certificates-hold)). Users of `gpg` or `sq` who trust the old primary can import this file and follow the vouch; users of `gpgv` and apt never read it, and learn of the new root key from the new package, signed by an old key.

## What each state does to the trust files

| Trust file | `active` | `retired` | `revoked` |
|---|---|---|---|
| Root list | Listed. | Not listed. | Not listed. |
| CA bundle | The certificate. | Not in it. | Not in it. |
| Keyring package | The primary and its bindings. | Not in it. | Not in it; its revocation signature is beside it. |
| CRL | One for the root key. | No more. | No more. |
| SSH CA key list | Its break-glass key. | Not listed. | Not listed. |
| `vouches/` | While `replaces` or the overlap holds. | Not made again. | Not made again. |

## In `root.json`

`root.json` is written once, by the ceremony that makes the key, and nothing changes it after ([the bundle](/reference/bundle/#rootjson)). A key added by a transition has two more members:

| Member | Meaning |
|---|---|
| `vouched_by` | The label of the root key that vouched. Absent for the keys the first `apply` made. |
| `vouches` | `{ "x509_sha256", "openpgp_sha256" }`: the digests of the two vouch files as first made. |

What a key replaces, until when, and when it is retired are in the wanted root file ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rules 3 and 4).

## The root of the year after a transition

The card that signs a yearly ceremony is the **card of the year**: the card whose root key signed longest ago. A root key that has never signed counts as the oldest, and a tie goes to the lowest key label. With two cards this is the alternation of [record 0007](../decisions/0007-changing-and-losing-a-root.md); after a replacement, the new card signs next, so its root key signs its CRL at that ceremony.

## The five transitions

Software to a PIV card, software to AWS KMS, a PIV card to AWS KMS, AWS KMS to a PIV card, and a card or a KMS key replaced by one of the same kind are one change of the wanted root file, with the new store's own checks ([cards](/reference/cards/#what-is-checked-on-a-card), [the cloud root](/reference/kms-root/#the-checks)). A store that gives no evidence cannot be the new root key's store unless it is the `software` store of a test root ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 10, and [record 0002](../decisions/0002-where-a-key-lives.md), rule 6). The [guides](/guides/) walk through each one.

## Test vectors

The cross-certificate and the certification come with vectors under `testdata/transitions/v1/` when the builder does: a valid pair; a cross-certificate that an old-root-only client accepts a chain through; one with a wrong issuer, a wrong subject, a missing authority key identifier and an expired validity; and a certification by a key that is not an active primary ([issue #13](https://github.com/truvity/ritueel/issues/13)).

## Follow-ups

- The commands, the checks and the vectors ([issue #13](https://github.com/truvity/ritueel/issues/13)).
- The lost-card drill that runs `revoke` and adds a root key ([issue #20](https://github.com/truvity/ritueel/issues/20)).

## Standards

| Standard | Used for |
|---|---|
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) | The cross-certificate: sections 4.1, 4.2.1.1 to 4.2.1.3 and 4.2.1.9, and path building through it. |
| [RFC 7093](https://datatracker.ietf.org/doc/html/rfc7093) | The key identifier. |
| [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | The certification and its subpackets. |
