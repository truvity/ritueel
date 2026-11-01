# SSH CA key list test vectors

Fixtures for the [SSH CA key list](../../docs/reference/ssh-ca-key-list.md): lists that a host must accept or refuse, given the list it holds and the root list it holds, and the file for `TrustedUserCAKeys` derived from a list, with the expected outcome and reason code of each in `v1/manifest.json`.

The roots are the test roots of the [hand-off vectors](../hand-off/README.md): A and B are active, Z is on no list. The list `seq7-a` is the list of the trust sequence the hand-off answers carry (7), and holds the keys of the accepted `ssh-ca-key` requests there and a break-glass key for each of A and B; the answers of type `ssh-ca-key` name the list their requester holds. Everything under `v1/` is public material made with throw-away software keys by `../hand-off/generate.py`, in the same run as the hand-off set; no private key is kept. A change to a vector that flips its outcome is a new format version (a new directory).

`just check-vectors` checks that the manifest names every tracked file, that the pins match the root files, that every list's signature verifies except the tampered one, that every list follows the members and rules of version 1 except the ones a case refuses on purpose, and that the `TrustedUserCAKeys` files are the user keys of the list they belong to.
