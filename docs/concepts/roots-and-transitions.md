---
title: Roots, intermediates and transitions
description: What a root of trust is, why there are several, how a new root takes over from an old one without breaking anyone, and what outsiders install.
sidebar:
  order: 1
---

*Design phase: this page teaches the model. The tools that carry out each step are planned; see the [roadmap](/roadmap/).*

## Two kinds of key

A chain of trust has two kinds of key, and they live different lives.

| | Root | Intermediate |
|---|---|---|
| What it is | The key that outsiders trust directly: an X.509 CA root certificate in a trust store, or an OpenPGP primary key in a keyring. | A key that a root has authorised to act for it: an intermediate CA certificate, or an OpenPGP subkey bound to a primary. |
| Used | Rarely: when an intermediate is created or renewed, or when the roots themselves change. Often once a year. | Every day, by software, to issue certificates or make signatures. |
| Held by | A person's care: a card in a drawer, a cloud key behind a confirmation. | A running system, close to the work. |
| Lifetime | Years. | Months, so that losing one is a small event. |
| Cost of a mistake | Every client that trusts it must learn the change. | Replace one intermediate; the root stays. |

The split exists so that the key that is expensive to lose is rarely used, and the key that is used all the time is cheap to replace. ritueel handles the left column. A system that holds intermediates, such as [sluis](https://sluis.id), handles the right.

## What a ceremony is

A *ceremony* is a root being used. It is interactive, because a person has to be present: they touch a YubiKey, or they confirm the use of a cloud key. It is also short, because everything that does not need the person is done for them. In ritueel a ceremony is one to three commands, and it leaves a record of what was done.

The most common ceremony is giving an intermediate its authority:

1. The system that will hold the intermediate makes its own key, so the key never travels, and sends a request. For X.509 the request is a PKCS#10 certificate request. For OpenPGP it is a public subkey together with a *back-signature*, made by the subkey itself, which proves that the holder of the subkey agreed to be bound.
2. The request carries *proof of where the key lives*: a YubiKey attestation certificate, or the description of a KMS key. A key that cannot prove it lives in a hardware store may be accepted or refused, depending on the policy you set.
3. ritueel checks the proof, shows the person what they are about to authorise (fingerprints, key store, lifetime), and asks for the touch or the confirmation.
4. The root signs. For X.509 that gives an intermediate CA certificate; for OpenPGP, a binding signature on the subkey. The result goes back to the system, which installs it.

The files that travel, and the checks on each side, are in the [hand-off contract](/reference/hand-off-contract/).

## Why more than one root

One root is a single point of failure. A card breaks, a cloud account is locked, a passphrase is forgotten, and every client that trusts only that root is stranded.

The remedy is two or more *independent* roots: separate keys, made separately, stored in different places, ideally on different kinds of store. Outsiders are given all of them at once, as one CA bundle or one keyring. Any one of them can authorise intermediates, so losing one does not stop you.

Two limits are worth knowing.

- Redundancy is not control. With standard tools, any single root that a client trusts can sign anything that client will accept. Standard X.509 and OpenPGP clients cannot ask for "two roots agreed". Protect each root as if it were the only one.
- A root key that is copied is not a second root, it is a second place to steal the same key. Redundancy means different keys.

## Moving from one root to another

Roots change: a key store is replaced, an algorithm ages, a root nears its expiry, or a root is lost. A change is a *transition*. A transition has four verbs, and a fifth for emergencies.

| Verb | Meaning |
|---|---|
| **Create** | Make the new root in its key store. Record where it lives and attest it if the store can. |
| **Vouch** | Let the old root vouch for the new one. For X.509 the old root issues a *cross-certificate* for the new root's key. For OpenPGP the old primary *certifies* the new primary. Now a client that trusts only the old root can still validate things signed under the new one. |
| **Overlap** | Run both. New intermediates are issued under the new root, while the old root stays trusted. Outsiders receive a bundle or keyring that holds both. |
| **Supersede** | Once every client has had time to learn the new root, publish a bundle or keyring without the old one. The old root is retired: no new intermediates, and it is removed from what you ship. |
| **Revoke** | The emergency exit. The old root is declared untrustworthy now. For OpenPGP this is a *revocation certificate*; for X.509, revocation of the cross-certificate and of the root through whatever channel your clients check. |

A transition, as it looks to an outsider:

| Step | The roots you ship | A client that trusts only the old root | A client that has the new bundle |
|---|---|---|---|
| Before | old | works | not applicable |
| Create, vouch | old | works; new things are vouched for by the old root | not applicable |
| Overlap | old and new | works | works |
| Supersede | new | must update, or it stops trusting new things | works |

The overlap is the part that is easy to get wrong. It must last as long as the slowest client you care about takes to update. Rushing it is how outages happen.

### Revocation is made in advance

A revocation certificate made after a key is lost cannot be made at all, and one made in a hurry is made on the worst day. So ritueel makes revocation material when a root is created, and stores it apart from the key. For OpenPGP it also names a *designated revoker* when the primary is created: another key that is allowed to revoke this one. A root can then be revoked even if its own card and passphrase are gone.

### Expiry is a transition too

A root that expires is a transition that is already scheduled. An expiring root, treated as an emergency on the last day, is a failure of planning. ritueel tracks expiry and warns before it, with enough lead time to run the overlap.

## What outsiders install

Outsiders should need only the tools they already have.

| For | They install | How it is made |
|---|---|---|
| TLS and other X.509 clients | A *CA bundle*: the root certificates in one PEM file, in the system or application trust store. | ritueel builds it from the current roots. |
| Package managers and `gpg` | A *keyring*: the public OpenPGP primary keys, usually delivered as a `.deb` or `.rpm` package that places them where the package manager looks. | ritueel provides the automation and the CLI that build the package. Your pipeline publishes it. |
| Systems that update their own trust | A *signed root list*: the current set of roots, with a version and an expiry, signed by a root that the client already trusts. A client refuses a list that is older than the one it has, or expired. | ritueel produces it. The client verifies it. |

A keyring package is also how a new OpenPGP root reaches people: the new package, signed by an old key, carries both keys during the overlap, and a package that drops the old key is the supersede step.

## What ritueel does not do

ritueel does not sign online, issue leaf certificates for servers or people, or store secrets. Those belong to the system that holds an intermediate. The two meet at standard formats: a certificate request in, a certificate or a binding signature out. Neither depends on the other ([ADR 0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)).

Next: [where a key lives](/concepts/key-stores/).
