---
title: Moving from one root to another
description: How a new root takes over from an old one without breaking anyone, with create, vouch, overlap, supersede and revoke, and what outsiders install.
sidebar:
  order: 19
---

*Design phase: this page teaches the model. The tools that carry out each step are planned; see the [roadmap](/roadmap/).*

Keys change. A key store is replaced, an algorithm ages, a key nears its expiry, or a key is lost. The step from one key to the next is a *transition*, and doing it without breaking anyone is the skill this page teaches. [The life of a root](/learn/life-of-a-root/) says when it happens; [why more than one key](/learn/layered-trust/) says why you are rarely left with only one.

## The five verbs

A transition has four verbs, and a fifth for emergencies.

| Verb | Meaning |
|---|---|
| **Create** | Make the new key in its key store. Record where it lives and attest it if the store can. |
| **Vouch** | Let the old key vouch for the new one. For X.509 the old key issues a *cross-certificate* for the new key. For OpenPGP the old primary *certifies* the new primary. Now a client that trusts only the old key can still validate things signed under the new one. |
| **Overlap** | Run both. New intermediates are issued under the new key, while the old key stays trusted. Outsiders receive a CA bundle or keyring that holds both. |
| **Supersede** | Once every client has had time to learn the new key, publish a CA bundle or keyring without the old one. The old key is retired: no new intermediates, and it is removed from what you ship. |
| **Revoke** | The emergency exit. The old key is declared untrustworthy now. For OpenPGP this is a *revocation signature*, plus a keyring without the old key, because some verifiers ignore the signature; for X.509, a signed root list without the old key, signed by the surviving keys and carrying its removal authorisation, made when it was born. |

A transition, as it looks to an outsider:

| Step | The keys you ship | A client that trusts only the old key | A client that has the new CA bundle |
|---|---|---|---|
| Before | old | works | not applicable |
| Create, vouch | old | works; new things are vouched for by the old key | not applicable |
| Overlap | old and new | works | works |
| Supersede | new | must update, or it stops trusting new things | works |

The overlap is the part that is easy to get wrong. It must last as long as the slowest client you care about takes to update. Rushing it is how outages happen.

### Revocation is made in advance

A revocation made after a key is lost cannot be made at all, and one made in a hurry is made on the worst day. So when a key is born, ritueel makes a revocation signature for its OpenPGP primary, and the holder stores it apart from the card. The key can then be revoked even if its card and PIN are gone. A revocation signature does not reach every verifier: for apt users the revocation is the new keyring package without the key ([the table](/learn/openpgp-release-keys/#revocation)). ritueel names no *designated revoker*, which the standard deprecates ([RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580), section 5.2.3.23).

### Expiry is a transition too

A key that expires is a transition that is already scheduled. An expiring key, treated as an emergency on the last day, is a failure of planning. A root key lasts about three years, and each use extends it: the next yearly ceremony that uses its card gives it a new validity of about three years (see [the ceremony](/tools/cli/#root-validity-and-its-extension)). A key whose card is dead or lost is not extended, so it shows itself by running out. ritueel tracks expiry and warns well before it, with enough lead time to run the overlap.

## In ritueel

You list the new key in the wanted root file, and `apply` makes an active key vouch for it. The retirement date ends the overlap, and `revoke` is the emergency exit. ritueel will not retire a key while something still hangs from it alone, and calls a set that is short of its target an alert. The states, the checks and the files are in [the transitions reference](/reference/transitions/), and the reasons in [record 0007](../decisions/0007-changing-and-losing-a-root.md).

An X.509 root key is not renamed: its name is inside the certificate, and every intermediate names it as issuer. A new name is a new key: add it, overlap, then retire the old one. An OpenPGP primary is different: a user ID can be added and retired without a new key ([personal OpenPGP](/reference/personal-openpgp/#changing-a-name-or-address)).

## What outsiders install

Outsiders need only the tools they already have. Every trust file carries one *trust sequence*, an integer that grows by one whenever any trust file changes, so a client can tell whether it is current ([record 0006](../decisions/0006-bundle-history-and-trust-files.md)).

| For | They install | How it is made |
|---|---|---|
| TLS and other X.509 clients | A *CA bundle*: the root certificates in one PEM file, in the system or application trust store. | ritueel builds it from the active keys. |
| Package managers and `gpg` | A *keyring*: the public OpenPGP primary keys and their subkeys, delivered as a `.deb` or `.rpm` package that places them where the package manager looks. | ritueel builds the keyring file. Your pipeline builds the package from it, signs it and publishes it. |
| Systems that update their own trust | A *signed root list*: the active root keys, pinned by their public keys, with the trust sequence and an expiry 13 months after signing, signed by one key. It is re-signed at every yearly ceremony and every transition. A client refuses an older list; when its list expires with no newer one, it keeps the last good list and warns. | ritueel produces it. The client verifies it. |
| X.509 clients that check revocation | A *CRL* for each root key, to load beside the CA bundle: it lists the intermediate certificates that were revoked. Certificates carry no address to fetch it from. | ritueel signs it with that key. The holder publishes it. The client loads it. |
| SSH hosts | An *SSH CA key list*: the SSH CA public keys that hosts trust, including the break-glass SSH CA that ritueel holds offline, signed and versioned like the root list. A system's key gets on it through the same hand-off as an intermediate. | ritueel produces it. The host verifies it. |

A keyring package is also how a new OpenPGP key reaches people: the new package, signed by an old key, carries both keys during the overlap, and a package that drops the old key is the supersede step.

## What ritueel does not do

ritueel does not sign online, issue leaf certificates for servers or people, or store secrets. Those belong to the system that holds an intermediate. The two meet at standard formats: a certificate request in, a certificate or a binding signature out. Neither depends on the other ([record 0001](../decisions/0001-what-ritueel-is.md)).

Next: [two roots in practice](/learn/two-roots/).
