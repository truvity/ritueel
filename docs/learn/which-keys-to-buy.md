---
title: Which keys to buy
description: Which hardware tokens to buy to learn and test ritueel, with what each supports, what it cannot do, and prices with the date they were read.
sidebar:
  order: 12.5
---

*Every fact on this page carries the date it was read, 2026-11-01 unless it says otherwise. Prices and firmware change; check the shop and the release notes before you buy. A device is called supported only after ritueel has been proven on it ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/)). Nothing here is built yet.*

You do not need hardware to learn the model: a drill runs on software test keys. You need hardware to practise the card parts of a ceremony, and to test a store before it is called supported. This page says what to buy for that, and what to leave on the shelf. Buy test devices only; never put a real root on a device you bought to experiment with.

## The short list

| Buy | Why | Price (date) |
|---|---|---|
| **A YubiKey 5 series, firmware 5.7 or later: three of them** | The reference device. Two for the root cards, one for the daily card. It is the one ritueel supports first. | About 75 to 80 EUR each. Not re-checked on the live store; confirm before you buy. |
| **One Nitrokey 3C NFC** | The second device to test: open firmware, an OpenPGP card with P-384 and touch confirmation, and a PIV applet with P-384. Read the gaps below first. | 65 EUR on the maker's shop (2026-11-01). |
| **A Nitrokey HSM 2, later, only if a PKCS#11 backend is planned** | The one device here built for key backup and a CA workflow through PKCS#11. | 109 EUR on the maker's shop (2026-11-01). |

Leave on the shelf: OnlyKey, SoloKeys and Token2, for the reasons below.

## What the devices support

| | YubiKey 5 (firmware 5.7 and 5.8) | Nitrokey 3 (firmware 1.9.1) | Nitrokey HSM 2 |
|---|---|---|---|
| PIV with P-384 | Yes | Yes, since firmware 1.8.2 | No PIV applet; it uses PKCS#11 |
| PIV attestation of a key | **Yes**, with a chain that ends at the maker's root | **No.** The attestation command returns "function not supported" | Not read in detail |
| PIV touch policy per key | Never, always or cached | **None found** in its source; a management-key option is parsed but unfinished | Not applicable |
| OpenPGP card with P-384 | Yes | Yes, with the secure-element backend that is the default | No OpenPGP card |
| OpenPGP touch confirmation | Yes | Yes | Not applicable |
| OpenPGP attestation | Yes, from firmware 5.2.3 | None found in its source | Not applicable |
| Firmware | Closed | Open source, apart from the secure element's operating system | Closed chip OS, open host software |
| Can a key be backed up? | No | No | By design, as a wrapped key; details not read |
| Certification | FIPS models exist | No FIPS 140 validation mentioned | No FIPS 140 |

Sources, read 2026-11-01: [YubiKey technical manual, PIV](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-piv.html) and [OpenPGP](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-openpgp.html); [Nitrokey 3 firmware releases](https://github.com/Nitrokey/nitrokey-3-firmware/releases), the [piv-authenticator source](https://github.com/trussed-dev/piv-authenticator), the [opcard-rs source](https://github.com/Nitrokey/opcard-rs), and the [Nitrokey documentation](https://docs.nitrokey.com/nitrokeys/features/openpgp-card/).

## The evidence gap, in plain words

A Nitrokey 3 cannot attest a key. A ceremony on a YubiKey checks a certificate that says "this key was made inside this token, with this policy", signed under the maker's published root. A Nitrokey 3 offers no such certificate, so a ceremony using it has no hardware evidence, and ritueel's ledger can only record "attestation unavailable". That is a real difference in what you can prove, not a detail. Its PIV applet is also young: the firmware notes since 1.8.0 do not call it beta, but fixes to the touch flag and a PIN retry counter were still unreleased on its main branch (read 2026-11-01), and its serial number and version are made up to look like a YubiKey's.

So the Nitrokey 3 is a good second device to **test** and to **support with the gap stated**, and a poor first choice for a root where attestation is the evidence.

## Why not the others

| Device | Why not |
|---|---|
| OnlyKey | Not a smartcard. It does GPG and SSH through its own agent, not through an OpenPGP card or PIV. |
| SoloKeys Solo 2 | FIDO2 and U2F only. Its latest tagged release is from 2022-08-25. |
| Token2 PIN+ | FIDO2 only, as far as the sources show. |
| Nitrokey Passkey | FIDO2 only. |
| Nitrokey Pro 2, Start, Storage 2 | Older devices with an OpenPGP card and no PIV. |
| YubiHSM 2 | Not a smartcard, with its own protocol, and the FIPS model costs about 935 to 1150 EUR at retailers. [ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/) takes no HSM for keys used once a year. |

## Cloud keys: nothing to buy, a lot to read

AWS KMS is the first cloud store. Google Cloud KMS and Azure Key Vault are planned ([Where a key lives](/learn/key-stores/#planned-stores)). All three sign a pre-computed SHA-384 digest with ECDSA P-384, which is all an X.509 certificate or an OpenPGP signature needs. **Nobody has run signing on Google Cloud or Azure for ritueel yet;** AWS has been measured. The differences that matter:

| | Google Cloud KMS | Azure Key Vault | AWS KMS |
|---|---|---|---|
| Attestation that a key was made in the HSM | Yes, for Cloud HSM keys | Not found | None |
| Signature encoding | DER | Probably raw r and s, which needs conversion (inferred, not stated) | DER |
| Replication | Locations such as `global` | Managed HSM replicates to one extended region | Multi-Region keys |
| Price, per key per month | About 2.50 USD for an HSM key (computed from hourly list prices, 2026-11-01) | About 5 USD for the first 250 HSM-protected keys; a Managed HSM about 2,300 USD (Azure price API, West Europe, 2026-11-01) | 1 USD (undated vendor page) |

## What to test with the devices

1. A ceremony's PIV part on each device: open, generate, sign, with the PIV library ritueel uses.
2. The OpenPGP card part: generate on the card, a P-384 signature, touch confirmation.
3. Wrong-PIN behaviour, and that ritueel stops before the card blocks.
4. The attestation check, expecting it to pass on the YubiKey and to be reported as unavailable on the Nitrokey, never as passed.
5. A card factory reset, which a Nitrokey firmware note lists as a known trouble in earlier versions.

Select a test device by its serial in your own environment; never write a serial number in the repository ([public content](/contributing/public-content/)).
