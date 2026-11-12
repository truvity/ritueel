---
title: A lost root card
description: What to do when a root card is lost, stolen or compromised. Revoke it, publish the new root list and keyring, add a replacement root, re-certify intermediates.
sidebar:
  order: 2
---

*Design phase: not built yet. The revocation behaviour of the verifiers was measured on 2026-11-01 (see [OpenPGP release keys](/learn/openpgp-release-keys/#revocation)); the drill has not run. This page is the plan that the commands `ritueel revoke` and `ritueel apply` will follow, and the drill that will rehearse it.*

Until the revocation reaches outsiders, whoever holds the card **and** its PIN can sign things they trust. A card without its PIN locks after three wrong tries, which limits the exposure. Act in this order.

## Steps

1. **Revoke the root key.** Fetch the stored revocation signature for your reason (*compromised* if the card may be in another's hands, *superseded* if it was lost safely) and the lost root key's removal authorisation, both made when the root key was born and stored apart from the card. Run `ritueel root revoke A --reason compromised --revocation FILE --removal FILE` with the surviving card. Publish the new root list, with a higher trust sequence and without the lost root key: the surviving root key signs it, and the lost root key's removal authorisation stands in for the signature it can no longer make, because a change of the root keys needs the signature or the stored removal authorisation of every active root key ([the root list](/reference/root-list/#who-signs)). For OpenPGP, publish the revocation signature that was made when the primary was born and stored apart from the card. The break-glass SSH CA key of the lost root key leaves the SSH CA key list with it. Result: clients that fetch the root list stop trusting the lost root key, hosts that fetch the SSH CA key list stop trusting its break-glass key, and users of `gpg` and Sequoia (`sqv`) who receive the signature stop trusting the lost primary. A user of `gpgv` or apt does not notice the signature; step 2 is what protects them.
2. **Publish new trust files without the lost root key.** A new CA bundle, and a new keyring file; your pipeline builds the package and signs it with the current subkey. The lost root key signs no more CRLs: it cannot sign one, and everything it issued dies with it. Result: new installs and package updates carry only the surviving root key. **For apt users this is the revocation:** `gpgv` ignores revocation signatures, so the lost primary stops being trusted only when the keyring package without it is installed.
3. **Add a replacement root key.** Write it in the wanted root file (`ritueel want`), on a fresh card or in a cloud key service; the number of keys in the file is the number of root keys you intend to have. Then run `ritueel apply` with the surviving card and the new card. The surviving root key vouches for it with an X.509 cross-certificate, and its primary is certified by the surviving primary. The surviving root key and the new root key both sign the new root list, and the new root key makes its own revocation signatures and removal authorisation: store them apart, as you did for the first keys. Result: two root keys again.
4. **Re-certify what chained only to the lost root key.** With alternating years this is the normal case: the intermediates of the year the lost card signed are signed again by the surviving card, over the same keys, without replacing any of them. Run `ritueel apply` again, as a ceremony of its own, with a fresh request from each intermediate over its same key; `ritueel status` calls them critical until then ([root transitions](/reference/transitions/#revoking-a-root-key)). Result: no intermediate has a certificate that depends on the lost root key.
5. **Publish the new trust files with the replacement root key,** after the overlap that your slowest client needs.
6. **Record it.** The ceremony record shows what was done, with which keys, and what outsiders now see.

If the pair of cards is shared by more than one bundle, run these steps in each bundle that has a root key on the lost card: the card is lost for all of them.

## How you know it worked

- A client with only the new root list refuses a certificate issued under the lost root key after the revocation.
- A host that had the old list refuses to accept an older list than the one it holds.
- A host that had the old list refuses a list that changes the root keys without the signature or the removal authorisation of every root key it holds ([the vectors](/reference/root-list/#test-vectors) show both).
- `gpgv` with the new keyring refuses a signature by a subkey the lost primary bound, because the new keyring no longer holds the lost primary. `gpgv` with the old keyring still accepts it, revoked or not.
- `sqv` with the old keyring and the revocation signature refuses it too. Do not use the exit status of `gpg --verify` for this check: it is 0 for a revoked key. Read `gpg --status-fd` for `REVKEYSIG`, or use `sqv`.

## What the drill checks

The drill runs on software roots in CI, then on rehearsal cards; it is part of [adopting the roots](/guides/root-adoption/). It starts with keys A and B of one root and one intermediate, takes a card out of use, and ends when the steps above have run and the checks pass. It records how long each step took, so the real time from loss to refusal is known.
