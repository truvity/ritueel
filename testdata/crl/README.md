# CRL test vectors

Fixtures for the [root-signed CRLs](../../docs/reference/crl.md): CRLs that a relying party must accept or refuse, given the CRL it holds and the roots it trusts, and certificates with the CRLs that list them or do not, with the expected outcome and reason code of each in `v1/manifest.json`.

The roots are the test roots of the [hand-off vectors](../hand-off/README.md): A and B are active, Z is on no list. Root A signed at trust sequence 7 and root B at trust sequence 6, and B's CRL is still current at the clock of the vectors (a CRL is valid for 25 months). Everything under `v1/` is public material made with throw-away software keys by `../hand-off/generate.py`, in the same run as the hand-off set; no private key is kept. A change to a vector that flips its outcome is a new format version (a new directory).

`just check-vectors` checks that the manifest names every tracked file, that the pins match the root files, that every CRL parses and has the number, times and revoked serials the manifest says, that its signature verifies except for the tampered one, and that each revocation case agrees with the CRL. The same files were run through `openssl verify -crl_check` (OpenSSL 3.5.5, 2026-11-01), which reports the listed certificate as revoked and the others as good.
