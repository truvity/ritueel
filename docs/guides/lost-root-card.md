---
title: A lost root card
description: What to do when a root card is lost, stolen or compromised: revoke, publish the new root list and keyring, add a replacement root, and re-certify the boards.
sidebar:
  order: 1
---

*Design phase: not built yet, and the revocation steps are assumed, not tested (see [OpenPGP release keys](/concepts/openpgp-release-keys/#revocation)). This page is the plan that the `root revoke` and `root add` commands will follow, and the drill that will rehearse it.*

Until the revocation reaches outsiders, whoever holds the card **and** its PIN can sign things they trust. A card without its PIN locks after three wrong tries, which limits the exposure. Act in this order.

## Steps

1. **Revoke the root.** Publish a root list signed by the surviving root, with a higher version and without the lost root. For OpenPGP, publish the revocation certificate that was made when the primary was born and stored apart from the card; the surviving primary is its designated revoker. Result: clients that fetch the root list stop trusting the lost root.
2. **Publish new trust products without the lost root.** A new CA bundle, and a new keyring package signed by the surviving key. Result: new installs and package updates carry only the surviving root.
3. **Add a replacement root.** Generate it on a fresh card or in a cloud key service (`root add`). The surviving root vouches for it with an X.509 cross-certificate, and its primary is certified by the surviving primary. Result: two roots again.
4. **Re-certify what chained only to the lost root.** With alternating years this is the normal case: the boards' intermediates of the year the lost card certified are certified again by the surviving card, without replacing any board key. Result: no board has a certificate that depends on the lost root.
5. **Publish the new trust products with the replacement root,** after the overlap that your slowest client needs.
6. **Record it.** The ceremony record shows what was done, with which keys, and what outsiders now see.

## How you know it worked

- A client with only the new root list refuses a certificate issued under the lost root's key after the revocation.
- A host that had the old list refuses to accept an older list than the one it holds.
- `gpgv` with the new keyring refuses a signature by a subkey the lost primary bound, once that subkey is revoked.

## What the drill checks

The drill uses test cards. It starts with two roots and one board, takes a card out of use, and ends when the steps above have run and the checks pass. It records how long each step took, so the real time from loss to refusal is known.
