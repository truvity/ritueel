---
title: Root transitions, version 1
description: The states of a root, root add, retire and revoke with their checks, the cross-certificate and the OpenPGP vouch, and what each state does to trust products.
sidebar:
  order: 11
---

*Not built yet. This is the page that [ADR 0009](/decisions/0009-root-transitions-vouch-overlap-retire-and-revoke/) leaves for the rules and profiles; the code is [issue #13](https://github.com/truvity/ritueel/issues/13), in M3. The ideas are taught in [Moving from one root to another](/learn/transitions/).*

A transition moves trust from one root to another without breaking a client that has not learned of the change. It never moves a key: the new root is born in its store, and an active root vouches for it ([principle 1](/principles/)).

## The state of a root

| State | Meaning | Set by |
|---|---|---|
| `active` | On the root list. It signs, its certificate is in the CA bundle, its primary is in the keyring package, it signs its CRL, and its break-glass key is on the SSH CA key list. | `init`, `root add` |
| `retired` | Ended in good order. It is in none of those products. What it certified is still certified by another active root. | `root retire` |
| `revoked` | Ended by loss, theft or compromise. As retired, and its revocation signature is published beside the keyring. | `root revoke` |

There is no state for the overlap. **An overlap is the time in which a root and the root that replaces it are both `active`.** The new root's `root.json` says so ([below](/reference/transitions/#in-rootjson)).

## The target

The number of active roots the holder intends to have is the **target**: `init` sets it to the number of roots it made (2 for two cards, 1 for a cloud root), and it is written in every record of `init`, `root add`, `root retire` and `root revoke` as `roots_target`. `status` compares it with the number of active roots:

| Active roots | Finding | Level |
|---|---|---|
| Fewer than the target | `root-set`: the set is short, so it names the roots that are missing. | alert (11) |
| More than the target, until the overlap ends | `root-overlap`: the date the overlap ends, and the roots involved. | notice (10) |
| More than the target, after that date | `root-overlap`: the overlap is overdue. | alert (11) |

`root add` without `--replaces` grows the set, and `root retire` without a replacement shrinks it. Neither is done by accident: both need `--target N`, which sets the new target.

## The commands

| Command | Needs | Writes |
|---|---|---|
| `ritueel root add --store S [--card SERIAL] [--replaces LABEL --overlap-until DATE \| --target N] [--root LABEL]` | The card, or the KMS roles, of the new root; the card or role of the vouching root. | The new root; its vouches; the next trust products. |
| `ritueel root retire LABEL [--now REASON] [--target N]` | The card of an active root other than `LABEL`. | A record, and the next trust products without `LABEL`. |
| `ritueel root revoke LABEL --reason REASON --revocation FILE [--target N]` | The card of an active root other than `LABEL`, and the stored revocation signature. | A record, the next trust products without `LABEL`, and the signature beside the keyring. |

`--overlap-until DATE` is a day in UTC and has no default: how long the overlap must last is the time that the slowest client you care about needs, and only the holder knows it ([Moving from one root to another](/learn/transitions/)). The vouching root is the root of the year unless `--root` names another, with the reason recorded, as for every ceremony.

### `root add`

1. The plan names the births ([ADR 0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#births-and-what-a-crash-leaves)): the new root's X.509 root key, OpenPGP primary and break-glass SSH CA key, with their revocation signatures ([Revocation material](/reference/revocation-material/)).
2. The new root's own certificate, self-signature and CRL are signed by the new keys.
3. The vouching root signs the cross-certificate and the OpenPGP certification below, with a touch each, and the new fingerprints have been shown before the touch.
4. The vouching root signs the next root list, with both roots, and the next CRL; the CA bundle, the SSH CA key list and the keyring are built with both.

### `root retire`

Refused unless all of these hold:

| Check | Code |
|---|---|
| At least one other root stays active. | `last-root` |
| The root is replaced by an active root (`replaces`), or `--target` lowers the target. | `target-required` |
| The overlap has ended (`overlap_until` has passed). `--now REASON` overrides this, and the reason is recorded. | `overlap-open` |
| Nothing depends on this root alone: every registered intermediate has a certificate, or a binding, from another active root over the same key, valid for at least 30 more days. | `still-needed` |

`still-needed` lists what is missing. The fix is a `yearly` ceremony with a fresh request for each intermediate over its same key, which an OpenPGP subkey also needs when a new primary joined after the subkey's request ([the contract](/reference/hand-off-contract/#the-request-1): a request back-signs for every active primary). The retired root's certificate is no longer in the bundle, its CRL is no longer written, and its primary leaves the keyring package.

### `root revoke`

It never waits for anything but the revocation signature, because it is the emergency exit.

| Check | Code |
|---|---|
| At least one other root stays active, and it can sign. | `last-root` |
| The file's digest equals the digest the ledger holds for this root and reason, and its signature verifies over the root's primary. | `revocation-mismatch`, `revocation-invalid` |

It then writes a root list, a bundle, a keyring and an SSH CA key list without the root, copies the revocation signature to `products/<sequence>/revocations/` (armoured, named by the fingerprint, as the [keyring page](/reference/keyring-package/#files) says), and stops writing the root's CRL. What the root alone had certified is **not** re-certified here: `status` reports each such intermediate as critical until a `yearly` ceremony does it, over the same keys ([A lost root card](/guides/lost-root-card/)).

## The vouch

Both vouches are signed by the vouching root, at the ceremony of `root add`, and are published in `products/<sequence>/vouches/`. They are not trust anchors and are in no bundle.

### The X.509 cross-certificate

`vouches/x509-<new>-by-<signer>.pem`, one certificate in PEM (RFC 7468).

| Field | Value |
|---|---|
| Version, serial | 3. A positive number of at most 20 bytes with at least 64 random bits. |
| Signature | `ecdsa-with-SHA384`, by the vouching root's X.509 key. |
| Issuer | The subject of the vouching root's current certificate. |
| Subject | The subject of the new root's certificate. |
| Subject public key | The new root's X.509 key. |
| Validity | `notBefore` is the ceremony time. `notAfter` is 13 calendar months later, as for an intermediate. It is made again by each `yearly` ceremony while the overlap lasts. |
| Basic constraints | Critical. `cA` true, no path length. |
| Key usage | Critical. `keyCertSign` and `cRLSign`. |
| Subject key identifier | The new key's, as in the [root certificate profile](/reference/directory/#the-root-certificate). |
| Authority key identifier | The vouching root's subject key identifier. |
| Name constraints | Absent: constraints belong to the intermediates. |
| Anything else | Absent: no CRL distribution point, no authority information access. |

A client that trusts only the old root can build a path from an intermediate that the new root issued: intermediate, then this certificate, then the old root. A client that has the new bundle needs it not at all.

### The OpenPGP certification

`vouches/openpgp-<new>-by-<signer>.pgp`, binary: the new primary's public key packet, its user ID, and one certification (RFC 9580, section 5.2.1.4, type `0x10`) made by the vouching primary over them. Its hashed area holds the signature creation time (the ceremony time), a signature expiration time of 13 calendar months, and the issuer fingerprint; its unhashed area holds the issuer key ID ([the packet rule](/reference/hand-off-contract/#issuer-key-id)). The hash is SHA-384.

It is **not in the keyring package**: that package holds only the primaries' own packets ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#the-keyring-package), [the keyring page](/reference/keyring-package/#what-the-certificates-hold)). Users of `gpg` or `sq` who trust the old primary can import this file and follow the vouch; users of `gpgv` and apt never read it, and learn of the new root from the new package, signed by an old key.

## What each state does to the trust products

| Product | `active` | `retired` | `revoked` |
|---|---|---|---|
| Root list | Listed. | Not listed. | Not listed. |
| CA bundle | The certificate. | Not in it. | Not in it. |
| Keyring package | The primary and its bindings. | Not in it. | Not in it; its revocation signature is beside it. |
| CRL | One for the root. | No more. | No more. |
| SSH CA key list | Its break-glass key. | Not listed. | Not listed. |
| `vouches/` | While `replaces` or the overlap holds. | Not made again. | Not made again. |

## In `root.json`

Written at `root add`, and not changed except the last three ([the directory](/reference/directory/#rootjson)).

| Member | Meaning |
|---|---|
| `replaces` | The label of the root this one replaces. Absent if it grows the set. |
| `overlap_until` | The day the overlap ends, UTC. Present when `replaces` is. |
| `vouched_by` | The label of the root that vouched. Absent for the roots `init` made. |
| `vouches` | `{ "x509_sha256", "openpgp_sha256" }`: the digests of the two vouch files as first made. |
| `retired_at`, `revoked_at`, `revoked_reason` | Present once the root is retired or revoked. |

## The root of the year after a transition

The root that signs a yearly ceremony is the **active root whose last signing record is the oldest**. A root that has never signed counts as the oldest, and a tie goes to the lowest label. With two cards this is the alternation of [ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#who-signs-and-when); after a replacement, the new root signs next, which also gives it a CRL signed by its own key soon after it is born.

## The five transitions

Software to a PIV card, software to AWS KMS, a PIV card to AWS KMS, AWS KMS to a PIV card, and a card or a KMS key replaced by one of the same kind are one command, `root add --store S`, with the new store's own checks ([cards](/reference/cards/#what-is-checked-on-a-card), [the cloud root](/reference/kms-root/#the-checks)). A store that gives no evidence cannot be the new root's store unless it is the `software` store of a test root ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#what-a-store-can-prove-decides-what-it-may-hold)). The [guides](/guides/) walk through each one.

## Test vectors

The cross-certificate and the certification come with vectors under `testdata/transitions/v1/` when the builder does: a valid pair; a cross-certificate that an old-root-only client accepts a chain through; one with a wrong issuer, a wrong subject, a missing authority key identifier and an expired validity; and a certification by a key that is not an active primary ([issue #13](https://github.com/truvity/ritueel/issues/13)).

## Follow-ups

- The commands, the checks and the vectors ([issue #13](https://github.com/truvity/ritueel/issues/13)).
- The lost-card drill that runs `root revoke` and `root add` ([issue #20](https://github.com/truvity/ritueel/issues/20)).

## Standards

| Standard | Used for |
|---|---|
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) | The cross-certificate: sections 4.1, 4.2.1.1 to 4.2.1.3 and 4.2.1.9, and path building through it. |
| [RFC 7093](https://datatracker.ietf.org/doc/html/rfc7093) | The key identifier. |
| [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | The certification and its subpackets. |
