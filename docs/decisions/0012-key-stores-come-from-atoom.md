# 0012 — Key stores come from the shared library atoom, linked into the one executable; a person's keys in a key file are the one exception

**Status:** Accepted
**Date:** 2026-11-26

## Decision

1. ritueel reaches a key store through the key port of [atoom](https://github.com/truvity/atoom), a shared library: the generated client, with the driver linked into ritueel's one executable. No second program runs, and no socket or network port is opened; the in-process link is an in-memory pipe.
2. The key stores are atoom's software driver, only for test roots; atoom's AWS KMS driver, for a cloud root; and, for cards, atoom's driver for the PIV application over direct USB, which an atoom decision record designs and nobody has built yet.
3. These stay ritueel's own: the ceremonies, plans and records; the OpenPGP packets and X.509 certificates it builds; the rules for the key directory; the removal and revocation files; the hand-off checks; and the day-to-day card's OpenPGP application, until atoom has a driver for it.
4. One exception: every key that record 0008 keeps in an encrypted key file lives in ritueel's own key file, and ritueel's own code uses it. These are a person's primary before stage two, adopted or not ([record 0008](0008-a-persons-own-key.md), rules 5 and 6), and the encryption subkey made in software ([record 0008](0008-a-persons-own-key.md), rule 10). For the primary, the exception ends when stage two has moved the root to its card-born keys.
5. ritueel is one static executable built with cgo off, and a card store is part of it.

## Why

- A key store is the part that is hardest to get right and costs most to keep. One library that several products use keeps each driver once; ritueel keeps what teaches and decides.
- The port takes no private key in or out, which is the rule of [record 0002](0002-where-a-key-lives.md), rule 2. An adopted key must come in, and the encryption subkey must be loaded onto each card, so rule 4 names them as the exception. The port also signs with P-256, P-384 and RSA-2048, and an adopted primary may be RSA-4096 or Ed25519.
- Direct USB needs no PC/SC service and no cgo, so the executable stays static (rule 5).
- atoom knows neither ritueel nor sluis, so [record 0001](0001-what-ritueel-is.md), rule 14, holds.
- The proposal and its options: [#311](https://github.com/truvity/ritueel/issues/311).

## What it costs

- ritueel depends on atoom's releases and pins one version.
- atoom's key contract is still alpha. A change there is taken together with a change here.
- The ConnectRPC and Protobuf runtimes of the key port become part of the executable.
- ritueel is not a network service: nothing listens for the key port.
- A key in a key file is used by ritueel's own code: the primary until stage two, the encryption subkey while it is made in software.
- A card store waits for atoom's driver, and the day-to-day card's OpenPGP store stays ritueel's own code until atoom has one ([record 0008](0008-a-persons-own-key.md), rule 13).

## Roads not taken

- **ritueel writes its own drivers for cards and cloud keys.** Full control, but a second copy of code that atoom keeps for every product, and ritueel keeps it alone.
- **atoom as a separate program, or a service on a socket.** The key store is walled off, but a second program to ship and a port to guard, in a tool that is not a network service.
- **A person's keys in atoom's software driver.** One path for every software key, but the port takes no private key in, cannot load a key onto a card, and signs neither RSA-4096 nor Ed25519.
- **Card stores through PC/SC and cgo.** The drivers exist, but a service on the host and cgo cost the static executable.

## Not yet proven or only proposed

- **Not yet proven.** atoom's driver for the PIV application over direct USB is designed and not built; until it is, ritueel has no `piv` store and stage two waits ([#204](https://github.com/truvity/ritueel/issues/204)).
- **Not yet proven.** atoom has no driver for the OpenPGP application of a card; until it has, the `openpgp-card` store is ritueel's own ([#18](https://github.com/truvity/ritueel/issues/18)).
