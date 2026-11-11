---
title: Research
description: Dated results of the spikes and research behind ritueel's decisions, each with its question, verdict, method and numbers, newest last.
sidebar:
  label: Overview
  order: 0
---

A research page answers one question, with the date it was measured, the verdict first, and the method and numbers that let someone repeat it ([how to write one](/contributing/research/)). Decision records quote the verdict and link here.

| Page | Question | Decided in |
|---|---|---|
| [Card libraries and tooling (2026-11-01)](/research/card-libraries-and-tooling-2026-11-01/) | Which code drives the root cards and a person's OpenPGP card? | [ADR 0003](https://github.com/truvity/ritueel/blob/d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee/docs/decisions/0003-key-stores-and-the-card-layer.md), now [record 0003](../decisions/0003-root-cards.md) |
| [OpenPGP verifier matrix (2026-11)](/research/openpgp-verifier-matrix-2026-11/) | What do `gpg`, `gpgv`, `sqv`, apt and rpm accept, and what does a revocation reach? | [ADR 0006](https://github.com/truvity/ritueel/blob/d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee/docs/decisions/0006-release-keys-and-the-keyring-package.md), now [record 0009](../decisions/0009-release-keys-and-the-keyring.md) |
| [Release key publication channels (2026-11-01)](/research/release-key-publication-channels-2026-11-01/) | Which channels beyond the first version should publish the release keys, and how do users verify? | [ADR 0006](https://github.com/truvity/ritueel/blob/d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee/docs/decisions/0006-release-keys-and-the-keyring-package.md), now [record 0009](../decisions/0009-release-keys-and-the-keyring.md) |
| [A wizard on localhost, the threats (2026-11-01)](/research/local-wizard-threats-2026-11-01/) | What must a page served on the user's own machine defend against, and what cannot be defended? | [ADR 0011](https://github.com/truvity/ritueel/blob/d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee/docs/decisions/0011-the-wizards-one-engine-three-faces-and-a-web-page-that-cannot-confirm-anything.md), now [record 0010](../decisions/0010-the-engine-the-process-and-the-page.md) |
| [Software key backends, 1Password and the OS keyring (2026-11-01)](/research/software-key-backends-2026-11-01/) | What can 1Password and the system keyring do as homes for software keys, and what are their limits? | [ADR 0003](https://github.com/truvity/ritueel/blob/d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee/docs/decisions/0003-key-stores-and-the-card-layer.md), now [record 0002](../decisions/0002-where-a-key-lives.md) |
| [What else keeps a private root today (2026-11-02)](/research/private-root-alternatives-2026-11-02/) | What do offline-pki, Smallstep's recipe, drduh's guide, OpenBao, YubiHSM 2, Sequoia and AWS KMS say they do? | [Compared](/learn/compared/) |
| [Retiring an OpenPGP subkey (2026-11-10)](/research/openpgp-subkey-retirement-2026-11-10/) | What do `gpgv`, `sqv` and `git verify-tag` do with signatures from a subkey that was revoked or has expired? | [ADR 0017](https://github.com/truvity/ritueel/blob/d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee/docs/decisions/0017-a-persons-openpgp-key-in-two-stages-an-adopted-primary-first-then-card-born-primaries.md), now [record 0008](../decisions/0008-a-persons-own-key.md) |
