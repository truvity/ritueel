---
title: How a YubiKey holds keys
description: What a YubiKey 5 holds, how PIV, OpenPGP and FIDO2 differ, how a PIV signature happens, and what locks or wipes a card.
---

*Design phase: ritueel is in design and has no release. Its OpenPGP-card store is planned for M3 and its PIV store for M6 ([roadmap](/roadmap/)); nothing on this page is built. The facts were read on 2026-11-10 in Yubico's documentation, in the FIDO and WebAuthn standards and in tool source, and nothing was measured on a card. Firmware numbers matter: a YubiKey 5 with older firmware does less.*

You are told the root is "on a YubiKey". What is in that card, what can wipe it, and what can it prove? This page opens a YubiKey 5 and shows what it holds, what limits it and how a signature happens.

It is link 1 of [the custody chain](/learn/custody-chain/): the card that holds a root. The ritual that makes a root card ready is [Prepare a root card](/guides/prepare-a-root-card/), and a lost or reset card is [Recover](/learn/recover/). The card is the hardware side of [where a key lives](/learn/key-stores/), and it gives the attestation that [what a key store can prove](/learn/what-a-store-can-prove/) relies on. [Which keys to buy](/learn/which-keys-to-buy/) says which cards to get, and [how a KMS key works](/learn/how-a-kms-key-works/) asks the same questions of a cloud key.

## What is inside

A YubiKey 5 carries several applications: one-time codes, OATH and U2F among them. Three hold keys that matter here: PIV, OpenPGP and FIDO2. Each has its own keys and its own PIN. Yubico describes the applications as separate, with separate storage for keys (YubiKey 5 applications page). A PIV reset has no effect on other applications such as FIDO (Yubico PIV PIN page).

| Application | Holds | Its lock |
|---|---|---|
| PIV | 24 key slots, plus one factory key (slot f9) that vouches for the others. A certificate can sit beside each key. | A PIN (6 to 8 characters), a PUK that unblocks the PIN, and a management key for writing slots |
| OpenPGP | 3 keys: one to sign, one to decrypt, one to authenticate | A PIN and an Admin PIN |
| FIDO2 | Passkeys. Up to 100 kept on the card (firmware 5.7.4 and later; 25 before). | One PIN |

PIV and OpenPGP use the smart-card interface of the card, and only one program can hold it at a time. FIDO2 has its own interface, HID.

**PIV: tries and wipes.**

- Three wrong PINs block the PIN. The PUK unblocks it, and three wrong PUKs block the PUK.
- The counters can be set from 1 to 255, for PIN and PUK together. Setting them resets both to their defaults.
- If both are blocked, only a PIV reset is left. It is possible only then, and it deletes the key in every slot.

**FIDO2: tries and wipes.**

- Three wrong PINs in a row need the card unplugged and plugged in again. Eight in a row lock the FIDO2 application.
- A FIDO reset needs no PIN. Plug the card in, ask within about ten seconds, and touch. It removes the FIDO2 PIN and every passkey, and it resets U2F too.
- The FIDO2 PIN is separate from the PIV PIN on a YubiKey 5.

## One PIV slot, up close

A slot is a numbered place for one private key. Four things belong to it.

- **The private key** is either generated on the card or imported. It can never be read out. A key born on a card has no copy.
- **The certificate** is a separate object. A slot can hold a key with no certificate. All certificates share about 50,000 bytes.
- **The PIN rule and the touch rule** are chosen when the key is made or loaded and can never be changed after. "Once" means once per session: until the card is unplugged or another application is used. "Always" means the PIN is asked right before every use. "Cached" touch means a touch counts for 15 seconds.
- **What a key can do** depends on its kind: sign, or agree on a shared secret (which is how decryption works). P-256, P-384 and RSA-2048 are on every YubiKey 5. RSA-3072, RSA-4096, Ed25519 and X25519 need firmware 5.7.4 in Yubico's tech manual (ykman checks 5.7.0).

| Slot | Standard name | Asks for the PIN by default | Note |
|---|---|---|---|
| 9a | authentication | once per session | Meant for signing in. |
| 9c | digital signature | every time | Meant for signing as an authority. |
| 9d | key management | once per session | Meant for decryption. |
| 9e | card authentication | never | Signs with no PIN by default. Keep it empty unless that is wanted. |
| 82 to 95 | retired key management (20 slots) | once per session | Extra slots, with no special meaning of their own. |
| f9 | attestation | not applicable | The factory key that vouches for the others. Never replace it. |

The default only applies when a key is made without stating a rule. The numbers are hexadecimal: 82 to 95 is twenty slots.

## How a PIV signature happens

1. **The program** picks the PIV application on the card.
2. **You: the PIN.** The program sends the PIN, if the slot's rule asks for it.
3. **The program** sends a digest and the slot number.
4. **You: the touch.** The card waits for a touch, if the rule asks for it.
5. **The card** signs inside and returns the signature.

Three things follow:

- The card sees only a digest. It cannot show you what it is signing, so the program that builds the digest must be trusted.
- A touch says that someone is at the card. It does not say which slot, or what for.
- Only one program can hold the smart-card side at a time. A card that `gpg` is using is closed to a PIV tool, and the other way round.

## The limits that shape a design

- **One PIN for all 24 slots.** When the management key is stored PIN-protected (a convention of ykman and other tools, not a firmware feature), whoever knows the PIN can authenticate as manager and overwrite or delete any slot. The management key authority is all-or-nothing, not scoped per slot (Yubico PIV admin access page). The slots are one area of trust, not twenty-four.
- **A blocked card can lose everything.** Three wrong PINs block the PIN. The PUK unblocks it. If both are blocked, only a reset is left, and it deletes every key.
- **Nothing can be changed after birth:** not the PIN rule, not the touch rule, not the firmware. Cards older than firmware 5.7 have a known weakness in ECDSA signing (CVE-2024-45678, Yubico advisory YSA-2024-03).
- **No key leaves the card.** So two cards, each with a key born on it, hold two different keys.
- **The card can vouch for a key.** For a key generated on it, the card issues a certificate that states: made on this card, with this serial, this firmware, this PIN rule and touch rule. Anyone can ask for it without the PIN. An imported key cannot get one.
- **The card can describe itself.** From firmware 5.3 it reports, per slot, the kind of key, the rules, whether it was generated or imported, and the public key.
- **One key can be deleted or moved** to another slot from firmware 5.7.4 in Yubico's tech manual (ykman checks 5.7.0). Before that, a slot could only be overwritten with a new key, or wiped by a PIV reset.

## The other two applications

**OpenPGP.** Three keys and no more: sign, decrypt, authenticate. So one identity per card. `gpg`, `git` and SSH through `gpg-agent` use it directly, without a PKCS#11 module, which a key in a PIV slot needs. Each key has its own touch setting. A key made on the card can be vouched for, as in PIV. Kinds: RSA up to 4096, P-256, P-384, P-521, Ed25519 (to sign and authenticate) and X25519 (to decrypt).

**FIDO2 (passkeys).** Passkeys have their own page: [How passkeys work](/learn/how-passkeys-work/).

## What each place is good for

| Job | Where | Why there |
|---|---|---|
| A root key (X.509 root or OpenPGP primary) | The root's row of the slot map: one slot for the X.509 root, one for the OpenPGP primary; PIN always, touch always | The card can vouch for the key, and the rules hold at every use ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/), [ADR 0016](/decisions/0016-several-bundles-share-one-pair-of-root-cards-and-the-bundle-keeps-a-card-inventory/#the-rows)) |
| Daily git signing and SSH sign-in | The OpenPGP application: a signing subkey and an authentication subkey | `gpg`, `git` and `ssh` use it without extra tools ([ADR 0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/)) |
| Opening the key file of a software key | A passkey of the kind the card does not keep, on each root card | The holder types a PIN and touches the card, and the file has no passphrase to lose ([ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/)); decided, not yet proven; [how a passkey opens a key file](/learn/how-passkeys-work/#a-passkey-that-opens-a-key-file) |

All three are designs, not built tools. For the same question asked of a cloud key, read [how a KMS key works](/learn/how-a-kms-key-works/).

## Sources

Read 2026-11-10.

- Yubico, [YubiKey 5 applications](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-index.html): applications are separate, with separate storage for keys.
- Yubico, [YubiKey 5 PIV](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-piv.html), [YubiKey 5 firmware 5.7](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-5.7.html) (key kinds, move and delete from 5.7.4, 100 passkeys from 5.7.4), [PIV certificate slots](https://developers.yubico.com/PIV/Introduction/Certificate_slots.html), [PIV admin access](https://developers.yubico.com/PIV/Introduction/Admin_access.html), [PIV PIN, PUK and management key](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-puk-mgmt-key.html), [PIV PIN and touch policies](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html), [PIV attestation](https://docs.yubico.com/yesdk/users-manual/application-piv/attestation.html) and [keeping track of keys](https://docs.yubico.com/yesdk/users-manual/application-piv/keeping-track.html) (the 5.3 metadata).
- Yubico, [YSA-2024-03](https://www.yubico.com/support/security-advisories/ysa-2024-03/): the ECDSA weakness (CVE-2024-45678).
- Yubico, [YubiKey 5 OpenPGP](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-openpgp.html): the three keys and their kinds; [OpenPGP attestation](https://developers.yubico.com/PGP/Attestation.html).
- Yubico, [YubiKey 5 FIDO](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-fido.html): PIN, tries and reset. The page still says "up to 25 resident keys" (older text); the firmware 5.7 page gives 100 from firmware 5.7.4.
- FIDO Alliance, [CTAP 2.2](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html): section 6.6 (reset).
