---
title: OpenPGP or Sigstore
description: How OpenPGP signing relates to Sigstore and keyless signing, what each proves, what each costs, and when to use one, the other or both.
sidebar:
  order: 13
---

Two ways to sign software are common, and they answer different questions. This page compares them so you can choose, and so that nobody says one replaces the other when it does not.

## The two ideas

**OpenPGP signs with a long-lived key.** You make a key, guard it, publish its fingerprint, and sign releases with it for years. A verifier needs the public key and nothing else, and can check offline.

**Sigstore's keyless signing uses a short-lived key and an identity.** At signing time the signer proves who they are with an OpenID Connect token, for example the token a CI system gives a job. A certificate authority issues a certificate that lasts minutes and binds a fresh key to that identity. The signature and the certificate are recorded in a public transparency log. The key is thrown away. A verifier checks that the certificate names the expected identity and that the entry is in the log.

How keyless signing works, in the project's words (read 2026-11-01): the client makes an ephemeral key, the certificate authority issues a certificate that is valid for 10 minutes and bound to the identity, the signature goes to the Rekor transparency log, and the key is discarded. The signature, the certificate and the log proof travel together in a *bundle*. Verifying after the certificate has expired needs the log entry proof or a timestamp.

## What each proves

| | OpenPGP | Sigstore keyless |
|---|---|---|
| **The signature says** | The holder of this key signed this. | This identity, for example this workflow in this repository, signed this at this time. |
| **What a verifier must know** | The public key or its fingerprint. | The expected identity and the issuer. |
| **What you guard** | A key, for years. | Nothing long-lived. The identity provider is the trust anchor. |
| **Verifies offline?** | Yes. | Partly: the log entry is checked online, or bundled with the signature. |
| **Who is trusted** | You, as the key's holder. | The identity provider, the certificate authority and the log. |
| **Fits package managers** | Yes: apt, rpm, `gpg` and `sqv` read it. | Not yet in most; used for container images, binaries and attestations. |
| **If the signer is compromised** | Revoke the key, and users must learn of it. | The identity is compromised: someone who can run the job signs. Fix the job. |
| **Custody question** | Where does the key live? | Who can run the workflow? |

## What is still moving

- The public-good service stays on the first version of the log by default (2026-06-28); the project paused the rollout of the second version on 2026-10-02 to build a post-quantum-ready log, aims for a production post-quantum instance in mid-2027, and tentatively plans to turn the classical instance down in 2029 or 2030.
- Offline verification needs the bundle, a trusted root and the pinned identity and issuer; the documentation has no single offline recipe.

Date any claim about it, and check the project's current plans before you build on one.

## When each fits

| If | Use |
|---|---|
| Users install with `apt`, `rpm` or `gpg`, and expect a key | OpenPGP. |
| Users must verify offline, or in an air-gapped place | OpenPGP. |
| You sign container images or build attestations from CI, and your users' tools check Sigstore | Sigstore. |
| You do not want a long-lived signing key to guard | Sigstore, and accept that the trust moves to the identity provider. |
| You want both a stable, offline-verifiable signature and provenance of how it was built | Both. |

## Both together

They compose. A release can carry an OpenPGP signature made with a release key held in a store, and a keyless attestation of how it was built. The first answers *who stands behind this file*, and the second *what built it*. Neither replaces the other: a keyless signature does not give a package manager a key it can pin, and an OpenPGP signature does not tell you the build was clean.

If you add keyless signing, remember it moves the custody chain. The question is no longer where a key lives, but who can run, change or approve the workflow that signs. Protect the branch, the workflow file and the identity provider's settings as you would a key.

## How ritueel relates

ritueel keeps the long-lived roots and the OpenPGP master keys. It does not run Sigstore. A release process can use ritueel's keys for the OpenPGP side and a keyless flow for provenance, and the two do not need to know about each other.
