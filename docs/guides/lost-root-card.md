---
title: A lost root card
description: What to do when a root card is lost, stolen or compromised. Revoke it, publish the new root list and keyring, add a replacement root, re-certify intermediates.
sidebar:
  order: 2
---

*Design phase: not built yet. The revocation behaviour of the verifiers was measured on 2026-11-01 (see [OpenPGP release keys](/concepts/openpgp-release-keys/#revocation)); the drill has not run. This page is the plan that the `root revoke` and `root add` commands will follow, and the drill that will rehearse it.*

Until the revocation reaches outsiders, whoever holds the card **and** its PIN can sign things they trust. A card without its PIN locks after three wrong tries, which limits the exposure. Act in this order.

## Steps

1. **Revoke the root.** Publish a root list signed by the surviving root, with a higher trust sequence and without the lost root. For OpenPGP, publish the revocation signature that was made when the primary was born and stored apart from the card. The lost root's break-glass SSH CA key leaves the SSH CA key list in the same ceremony. Result: clients that fetch the root list stop trusting the lost root, hosts that fetch the SSH CA key list stop trusting its break-glass key, and users of `gpg` and Sequoia (`sqv`) who receive the signature stop trusting the lost primary. A user of `gpgv` or apt does not notice the signature; step 2 is what protects them.
2. **Publish new trust products without the lost root.** A new CA bundle, and a new keyring package signed by the surviving key. The lost root publishes no more CRLs: it cannot sign one, and everything it issued dies with it. Result: new installs and package updates carry only the surviving root. **For apt users this is the revocation:** `gpgv` ignores revocation signatures, so the lost primary stops being trusted only when the keyring package without it is installed.
3. **Add a replacement root.** Generate it on a fresh card or in a cloud key service (`root add`). The surviving root vouches for it with an X.509 cross-certificate, and its primary is certified by the surviving primary. Result: two roots again.
4. **Re-certify what chained only to the lost root.** With alternating years this is the normal case: the intermediates of the year the lost card signed are signed again by the surviving card, over the same keys, without replacing any of them. Result: no intermediate has a certificate that depends on the lost root.
5. **Publish the new trust products with the replacement root,** after the overlap that your slowest client needs.
6. **Record it.** The ceremony record shows what was done, with which keys, and what outsiders now see.

## How you know it worked

- A client with only the new root list refuses a certificate issued under the lost root's key after the revocation.
- A host that had the old list refuses to accept an older list than the one it holds.
- `gpgv` with the new keyring refuses a signature by a subkey the lost primary bound, because the new keyring no longer holds the lost primary. `gpgv` with the old keyring still accepts it, revoked or not.
- `sqv` with the old keyring and the revocation signature refuses it too. Do not use the exit status of `gpg --verify` for this check: it is 0 for a revoked key. Read `gpg --status-fd` for `REVKEYSIG`, or use `sqv`.

## What the drill checks

The drill runs on software roots in CI, then on test cards; it is part of [adopting the roots](/guides/root-adoption/). It starts with two roots and one intermediate, takes a card out of use, and ends when the steps above have run and the checks pass. It records how long each step took, so the real time from loss to refusal is known.
