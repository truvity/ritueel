# Root list test vectors

Fixtures for the [signed root list and the CA bundle](../../docs/reference/root-list.md): root lists that a host must accept or refuse, given the list it already holds, and CA bundles with their trust sequence, with the expected outcome and reason code of each in `v1/manifest.json`.

The roots are the test roots of the [hand-off vectors](../hand-off/README.md): A and B are active, Z is on no list. `pki/` holds copies of their certificates and OpenPGP primaries, and the list `seq7-a` is the root list of the trust sequence the hand-off answers carry (7). Everything under `v1/` is public material made with throw-away software keys by `../hand-off/generate.py`, in the same run as the hand-off set; no private key is kept. The record digests in the lists are made up. A change to a vector that flips its outcome is a new format version (a new directory).

`just check-vectors` checks that the manifest names every tracked file, that the pins match the root files, that every list's signature verifies except the tampered one, and that each bundle holds the roots it names under its trust sequence.
