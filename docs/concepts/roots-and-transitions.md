---
title: Roots, intermediates and transitions
description: What a root of trust is, why there are several, how a new root takes over from an old one without breaking anyone, and what outsiders install.
sidebar:
  order: 2
---

*Design phase: this page teaches the model. The tools that carry out each step are planned; see the [roadmap](/roadmap/).*

## Two kinds of key

A chain of trust has two kinds of key, and they live different lives.

| | Root | Intermediate |
|---|---|---|
| What it is | The key that outsiders trust directly: an X.509 CA root certificate in a trust store, or an OpenPGP primary key in a keyring. | A key that a root has authorised to act for it: an intermediate CA certificate, or an OpenPGP subkey bound to a primary. |
| Used | Rarely: when an intermediate is created or renewed, or when the roots themselves change. Often once a year. | Every day, by software, to issue certificates or make signatures. |
| Held by | A person's care: a card in a drawer, a cloud key behind a confirmation. | A running system, close to the work. |
| Lifetime | Years, extended at each use. | Months, so that losing one is a small event. The yearly ceremony renews it by re-signing the same key. |
| Cost of a mistake | Every client that trusts it must learn the change. | Replace one intermediate; the root stays. |

The split exists so that the key that is expensive to lose is rarely used, and the key that is used all the time is cheap to replace. ritueel handles the left column. A system that holds intermediates, such as [sluis](https://sluis.id), handles the right.

## What a ceremony is

A *ceremony* is a root being used. It is interactive, because a person has to be present: they touch a YubiKey, or they confirm the use of a cloud key. It is also short, because everything that does not need the person is done for them. In ritueel a ceremony is one to three commands, and it leaves a record of what was done.

The most common ceremony is giving an intermediate its authority, and the same ceremony renews it every year by signing again over the same key. An intermediate key is replaced only on an event (a suspected compromise, a change of store or algorithm, a change of custody) or at most every three years.

1. The system that will hold the intermediate makes its own key, so the key never travels, and sends a request. For X.509 the request is a PKCS#10 certificate request. For OpenPGP it is a public subkey together with *back-signatures*, one for every active root and made by the subkey itself, which prove that the holder of the subkey agreed to be bound. With one for each root, either root can make the binding.
2. The request carries *proof of where the key lives*: a YubiKey attestation certificate, or the description of a KMS key. A key that cannot prove it lives in a hardware store may be accepted or refused, depending on the policy you set.
3. ritueel checks the proof, shows the person what they are about to authorise (fingerprints, key store, lifetime), and asks for the touch or the confirmation.
4. The root signs. For X.509 that gives an intermediate CA certificate; for OpenPGP, a binding signature on the subkey. The result goes back to the system, which installs it.

The files that travel, and the checks on each side, are in the [hand-off contract](/reference/hand-off-contract/).

## Why more than one root

One root is a single point of failure: a card breaks, an account is locked, and every client that trusts only that root is stranded. So there is a second, *independent* root, a different key made separately, and outsiders install both at once. Any one of them can authorise intermediates.

How many roots depends on the store, because **redundancy protects against loss, not against compromise**. A card cannot be copied, so cards come in two; a cloud key service can replicate its key, so a cloud root is one key with a replica, which is the same key and not a second root ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/)). Redundancy is not control either: any one root a client trusts can sign anything that client accepts, so protect each root as if it were the only one.

## Moving from one root to another

Roots change: a key store is replaced, an algorithm ages, a root nears its expiry, or a root is lost. A change is a *transition*. A transition has four verbs, and a fifth for emergencies.

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

A revocation made after a key is lost cannot be made at all, and one made in a hurry is made on the worst day. So when a root is born, ritueel makes a revocation signature for its OpenPGP primary, and the holder stores it apart from the card. The root can then be revoked even if its card and PIN are gone. A revocation signature does not reach every verifier: for apt users the revocation is the new keyring package without the key ([the table](/concepts/openpgp-release-keys/#revocation)). ritueel names no *designated revoker*, which the standard deprecates ([RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580), section 5.2.3.23).

### Expiry is a transition too

A root that expires is a transition that is already scheduled. An expiring root, treated as an emergency on the last day, is a failure of planning. A root lasts about three years, and each use extends it: the next yearly ceremony that uses its card gives it a new validity of about three years (see [the ceremony](/concepts/ceremonies/#root-validity-and-its-extension)). A root whose card is dead or lost is not extended, so it shows itself by running out. ritueel tracks expiry and warns well before it, with enough lead time to run the overlap.

## What outsiders install

Outsiders need only the tools they already have. Every product carries one *trust sequence*, an integer that grows by one whenever any of them changes, so a client can tell whether it is current ([ADR 0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/)).

| For | They install | How it is made |
|---|---|---|
| TLS and other X.509 clients | A *CA bundle*: the root certificates in one PEM file, in the system or application trust store. | ritueel builds it from the current roots. |
| Package managers and `gpg` | A *keyring*: the public OpenPGP primary keys and their subkeys, delivered as a `.deb` or `.rpm` package that places them where the package manager looks. | ritueel builds the package. Your pipeline signs and publishes it. |
| Systems that update their own trust | A *signed root list*: the current roots pinned by their public keys, with the trust sequence and an expiry 13 months after signing, signed by one root. It is re-signed at every yearly ceremony and every transition. A client refuses an older list; when its list expires with no newer one, it keeps the last good list and warns. | ritueel produces it. The client verifies it. |
| SSH hosts | An *SSH CA key list*: the SSH CA public keys that hosts trust, including the break-glass SSH CA that ritueel holds offline, signed and versioned like the root list. | ritueel produces it. The host verifies it. |

A keyring package is also how a new OpenPGP root reaches people: the new package, signed by an old key, carries both keys during the overlap, and a package that drops the old key is the supersede step.

## What ritueel does not do

ritueel does not sign online, issue leaf certificates for servers or people, or store secrets. Those belong to the system that holds an intermediate. The two meet at standard formats: a certificate request in, a certificate or a binding signature out. Neither depends on the other ([ADR 0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)).

Next: [where a key lives](/concepts/key-stores/).
