---
title: Revoke a key
description: Revoke a compromised or lost key with the pre-made OpenPGP revocation certificate or a CRL for an X.509 intermediate, and publish trust products without it.
sidebar:
  order: 5
---

*Design phase: not built yet. This page is the plan that `ritueel intermediate revoke` and `root revoke` will follow, and the plan for the revocation certificates that `init` will make. Read [Revoke](/learn/revoke/) first.*

## What you start with

- The reason, chosen honestly: a hard reason (compromised) or a soft one (superseded, retired).
- For an OpenPGP key: the revocation certificate made at creation, from its place apart from the card.
- For an X.509 intermediate: the card of each root that issued one of its certificates which has not expired.

## Revoke an OpenPGP key

1. **Fetch the revocation certificate** for your reason from its stored place, and run `ritueel revocation check FILE`. Result: you hold the right file, and ritueel has printed nothing of it. Use the *compromised* file if the key may be in another's hands, and the *superseded* file if it was safe and has been replaced ([Revoke](/learn/revoke/#reasons-matter)).
2. **Publish it:** to your key directory or website, and to the places people look for your key.
3. **Publish a keyring package without the key.** `ritueel keyring build`, then your pipeline. Result: apt users, whose `gpgv` ignores revocation signatures, are protected when the package arrives.
4. **Tell people** which fingerprint to stop trusting, and which to trust.

## Revoke an X.509 intermediate

1. `ritueel intermediate revoke NAME --reason compromise`. The plan names the roots whose CRLs get an entry. Result: those roots sign new CRLs listing the certificate.
2. **Publish the CRLs** with the next trust sequence. Clients that load them reject the certificate.
3. **Issue a replacement** if one is needed: see [Rotate a key](/guides/rotate-a-key/).

## Revoke a root

For a root that is lost, stolen or compromised, use [A lost root card](/guides/lost-root-card/): `ritueel root revoke LABEL --reason REASON --revocation FILE` ([the checks](/reference/transitions/#root-revoke)).

## How you know it worked

- `sqv` with the new keyring and the revocation refuses a signature by the revoked key.
- `gpgv` with the new keyring refuses it because the key is gone. Do not rely on `gpg --verify`'s exit status for this check.
- A client with the new CRL refuses the revoked certificate.

## Drill

Revoke a software test key and check each verifier in the table above. Then do it once with a test card whose revocation certificate is in its stored place. The record says how long it took from decision to refusal.
