---
title: Moving from one root to another
description: How a new root takes over from an old one without breaking anyone, with create, vouch, overlap, supersede and revoke, and what outsiders install.
sidebar:
  order: 19
---

*Design phase: this page teaches the model. The tools that carry out each step are planned; see the [roadmap](/roadmap/).*

Roots change. A key store is replaced, an algorithm ages, a root nears its expiry, or a root is lost. The step from one root to the next is a *transition*, and doing it without breaking anyone is the skill this page teaches. [The life of a root](/learn/life-of-a-root/) says when it happens; [why more than one root](/learn/layered-trust/) says why you are rarely left with only one.

## The five verbs

A transition has four verbs, and a fifth for emergencies.

| Verb | Meaning |
|---|---|
| **Create** | Make the new root in its key store. Record where it lives and attest it if the store can. |
| **Vouch** | Let the old root vouch for the new one. For X.509 the old root issues a *cross-certificate* for the new root's key. For OpenPGP the old primary *certifies* the new primary. Now a client that trusts only the old root can still validate things signed under the new one. |
| **Overlap** | Run both. New intermediates are issued under the new root, while the old root stays trusted. Outsiders receive a bundle or keyring that holds both. |
| **Supersede** | Once every client has had time to learn the new root, publish a bundle or keyring without the old one. The old root is retired: no new intermediates, and it is removed from what you ship. |
| **Revoke** | The emergency exit. The old root is declared untrustworthy now. For OpenPGP this is a *revocation signature*, plus a keyring without the old key, because some verifiers ignore the signature; for X.509, a signed root list without the old root, signed by a surviving root. |

A transition, as it looks to an outsider:

| Step | The roots you ship | A client that trusts only the old root | A client that has the new bundle |
|---|---|---|---|
| Before | old | works | not applicable |
| Create, vouch | old | works; new things are vouched for by the old root | not applicable |
| Overlap | old and new | works | works |
| Supersede | new | must update, or it stops trusting new things | works |

The overlap is the part that is easy to get wrong. It must last as long as the slowest client you care about takes to update. Rushing it is how outages happen.

### Revocation is made in advance

A revocation made after a key is lost cannot be made at all, and one made in a hurry is made on the worst day. So when a root is born, ritueel makes a revocation signature for its OpenPGP primary, and the holder stores it apart from the card. The root can then be revoked even if its card and PIN are gone. A revocation signature does not reach every verifier: for apt users the revocation is the new keyring package without the key ([the table](/learn/openpgp-release-keys/#revocation)). ritueel names no *designated revoker*, which the standard deprecates ([RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580), section 5.2.3.23).

### Expiry is a transition too

A root that expires is a transition that is already scheduled. An expiring root, treated as an emergency on the last day, is a failure of planning. A root lasts about three years, and each use extends it: the next yearly ceremony that uses its card gives it a new validity of about three years (see [the ceremony](/tools/cli/#root-validity-and-its-extension)). A root whose card is dead or lost is not extended, so it shows itself by running out. ritueel tracks expiry and warns well before it, with enough lead time to run the overlap.

## In ritueel

`root add` makes the new root and has an active root vouch for it, `root retire` ends the overlap, and `root revoke` is the emergency exit. You say how long the overlap lasts; ritueel refuses to retire a root while something still hangs from it alone, and calls a set that is short of its target an alert. The states, the checks and the files are in [the transitions reference](/reference/transitions/), and the reasons in [ADR 0009](/decisions/0009-root-transitions-vouch-overlap-retire-and-revoke/).

## What outsiders install

Outsiders need only the tools they already have. Every product carries one *trust sequence*, an integer that grows by one whenever any of them changes, so a client can tell whether it is current ([ADR 0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/)).

| For | They install | How it is made |
|---|---|---|
| TLS and other X.509 clients | A *CA bundle*: the root certificates in one PEM file, in the system or application trust store. | ritueel builds it from the current roots. |
| Package managers and `gpg` | A *keyring*: the public OpenPGP primary keys and their subkeys, delivered as a `.deb` or `.rpm` package that places them where the package manager looks. | ritueel builds the package. Your pipeline signs and publishes it. |
| Systems that update their own trust | A *signed root list*: the current roots pinned by their public keys, with the trust sequence and an expiry 13 months after signing, signed by one root. It is re-signed at every yearly ceremony and every transition. A client refuses an older list; when its list expires with no newer one, it keeps the last good list and warns. | ritueel produces it. The client verifies it. |
| X.509 clients that check revocation | A *CRL* for each root, to load beside the CA bundle: it lists the intermediate certificates that were revoked. Certificates carry no address to fetch it from. | ritueel signs it with the root. The operator publishes it. The client loads it. |
| SSH hosts | An *SSH CA key list*: the SSH CA public keys that hosts trust, including the break-glass SSH CA that ritueel holds offline, signed and versioned like the root list. A system's key gets on it through the same hand-off as an intermediate. | ritueel produces it. The host verifies it. |

A keyring package is also how a new OpenPGP root reaches people: the new package, signed by an old key, carries both keys during the overlap, and a package that drops the old key is the supersede step.

## What ritueel does not do

ritueel does not sign online, issue leaf certificates for servers or people, or store secrets. Those belong to the system that holds an intermediate. The two meet at standard formats: a certificate request in, a certificate or a binding signature out. Neither depends on the other ([ADR 0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)).

Next: [two roots in practice](/learn/two-roots/).
