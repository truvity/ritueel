---
title: Two sources from the earlier records (2026-11-11)
description: The sources of the 2024 side channel in some security keys, and the tests a planned key store passes before it is taught; carried over from earlier records.
sidebar:
  order: 9
---

## Question

Two points were held only by the first eighteen records and are in none of the ten records that replaced them: what is the source of the 2024 side channel in some security keys, which the [Rotate page](../learn/rotate.md) gives as an example, and which tests does a planned key store pass before it is called supported?

## When

Carried over on 2026-11-11 from the records at commit `d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee` (the sources of the side channel are in the record on a person's own OpenPGP key, the tests in the record on key stores and the card layer). The sources were read on 2026-11-02 and were not read again today, so they are **UNVERIFIED today**: the pages can have changed.

## Verdict

The example on the Rotate page stands: it has these sources. The admission list below is the one the [roadmap](../roadmap.md) summarises for planned stores, and it fits rules 1 and 16 of [record 0002](../decisions/0002-where-a-key-lives.md) and rule 8 of [record 0008](../decisions/0008-a-persons-own-key.md).

## The 2024 side channel in a card's signature code

In 2024 a side channel in the ECDSA implementation of a cryptographic library used inside some security keys let an attacker with physical access and specialised equipment recover an ECDSA private key.

- The vulnerability is CVE-2024-45678: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-45678). The researchers' write-up is at [ninjalab.io/eucleak](https://ninjalab.io/eucleak/).
- The devices already made accepted no firmware update, as the maker's advisory says: [YSA-2024-03](https://www.yubico.com/support/security-advisories/ysa-2024-03/).
- So the remedy was a new device, and a key made in the old one had to be replaced. This is why a key on a card is replaced on an event and not by calendar: rule 16 of [record 0002](../decisions/0002-where-a-key-lives.md) and rule 8 of [record 0008](../decisions/0008-a-persons-own-key.md) list an advisory about the device or its firmware as the first event.

Sources read on 2026-11-02 and not read again on 2026-11-11 (UNVERIFIED today).

## The tests a planned key store passes

Google Cloud KMS, Azure Key Vault ([issue #67](https://github.com/truvity/ritueel/issues/67)) and other hardware such as Nitrokey ([issue #66](https://github.com/truvity/ritueel/issues/66)) are planned. A store is admitted, and called supported, when all of these hold, and not before:

1. **A real installation needs it** ([principle 8](../principles.md)): a real account or a real device, not an imagined one.
2. **A dated research page measures it:** a P-384 signature over a SHA-384 digest, the evidence it gives and how it is checked, how a second process or machine reaches it, what a replica or a backup is, and what a reset or a deletion does.
3. **Its evidence kind is stated,** which fixes what it may hold. A token that cannot attest holds no root.
4. **It passes the tagged tests of its kind** on a real device or account, selected by serial number or by test account.
5. **The site compares it** on [Where a key lives](../learn/key-stores.md) and a guide walks the transition into it.

Whether a new token joins `piv` or `openpgp-card` or stands alone is decided after step 2.

Rule 1 of [record 0002](../decisions/0002-where-a-key-lives.md) says a store is called supported only after it is proven on real hardware or a real account; the five tests above are the longer form of it.

## Roads not taken

None.

## Changes made

None.
