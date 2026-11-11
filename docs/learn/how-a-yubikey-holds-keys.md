---
title: How a YubiKey holds keys
description: What a YubiKey 5 holds, how PIV, OpenPGP and FIDO2 differ, how a PIV signature and a passkey sign-in happen, and what locks or wipes a card.
sidebar:
  order: 12.3
---

*Design phase: ritueel is in design and has no release. Its OpenPGP-card store is planned for M3 and its PIV store for M6 ([roadmap](/roadmap/)); nothing on this page is built. The facts were read on 2026-11-10 in Yubico's documentation, in the FIDO and WebAuthn standards and in tool source, and nothing was measured on a card. The passkey sections were read again on 2026-11-11. Firmware numbers matter: a YubiKey 5 with older firmware does less.*

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

**FIDO2 (passkeys).** The next part opens this one.

## Passkeys in brief

A passkey is what the FIDO2 standard calls a credential. The card makes a new key pair for each passkey, for one site name (the standards call it the relying party ID, usually a domain name such as `example.com`). The private key never leaves the card: it is kept there, or rebuilt inside it from a key handle (see the table). The site keeps the public key. A passkey works for its own site name only, and the card offers it to no other.

There are two kinds, and the difference matters for a loss:

| | Kept on the card | Not kept on the card |
|---|---|---|
| Also called | discoverable; the older name is resident key | non-discoverable |
| Where it lives | On the card, with the site name, an account id and a display name | Nowhere on the card: Yubico states that no information is stored on the YubiKey |
| How many | At most 100 (firmware 5.7.4 and later; 25 before; Yubico firmware 5.7 page) | No limit |
| Who keeps the key handle | Nobody; the card finds the passkey by site name | The program or site that asked for it, and it must hand the key handle back each time |
| After a FIDO reset | Erased | Stops working |

A passkey not kept on the card is rebuilt from a **key handle** (the standards call it the credential id), a blob that the card gave out when the passkey was made. A passkey kept on the card can be deleted one by one, with the PIN, from firmware 5.2.1. A new card has no FIDO2 PIN (Yubico FIDO page).

**A secret from a passkey.** A program can also ask a card for a secret that only that passkey on that card makes for a given input. The standard calls it hmac-secret, and browsers call it PRF. The card refuses to give it without a touch. The same passkey with the same input gives the same secret, and it depends on whether the PIN was checked, not on the PIN's value (CTAP 2.2, section 12.7; Yubico's hmac-secret deep dive).

**What the card says when a passkey is made.** Its attestation carries the model identifier (the AAGUID). Yubico states that a serial number is not shared (Securing WebAuthn with Attestation). With enterprise attestation, the serial number can be sent to a site that the card's list names: from firmware 5.7 (Yubico FIDO page). A FIDO reset turns it off again, and `ykman` turns it on. Compare PIV: a PIV key's certificate names this card's serial number, and a passkey's names only the model.

**One loss ends every passkey.** One FIDO reset wipes every passkey on a card. Yubico's guide to PRF says a lost authenticator means lost data, and recommends wrapping a key for several authenticators.

**A synced passkey is a different thing.** Its private key is copied, encrypted, to your other devices through a cloud account, and can be recovered through the account. The card's guarantee that the key stays in one place is gone. NIST bars syncable keys at its highest assurance level for that reason (SP 800-63B-4). So a synced passkey is not a root-level store.

## Passkeys up close

The brief section says what a passkey is. This one follows a passkey through its life: what one holds, why a hundred do not get in each other's way, what the PIN and the touch guard, how a sign-in goes, and how the same passkey can open a key file. The facts in this part were read on 2026-11-11 in the WebAuthn standard, in Yubico's documentation, in OpenSSH's notes and in two other public notes; all are listed under Sources.

### One passkey, and why a hundred do not collide

A passkey kept on the card is one record. It holds a private key, the site name, an account id (the standard's "user handle") and, in the standard's words, other information the card may keep to show you, such as a display name ("otherUI"; WebAuthn Level 3, the public key credential source). Two things keep a hundred such records apart.

- **Each has its own key pair.** Using one passkey never touches another.
- **Each is bound to one site name.** The card offers a passkey to the site it was made for only, and what the card signs begins with a hash of that site name, which the site checks together with the challenge it sent. So a signature made for one site fails the check at any other (WebAuthn Level 3, "Relying Party Identifier" in section 4, sections 6.1 and 7.2).

Two accounts at the same site are two passkeys with the same site name and different account ids: the standard says authenticators map pairs of site name and user handle to credential sources (WebAuthn Level 3).

### Kept on the card, or rebuilt from a key handle

**Kept on the card.** The card holds the whole record. A site can ask the card, "do you have a passkey for `example.com`?" without knowing who is signing in. That is how a sign-in with no user name works (Yubico FIDO page).

**Not kept on the card.** The card holds nothing for it. The passkey is rebuilt from the **key handle** that the site or the program keeps and hands back at each use. OpenSSH's notes explain how this works for U2F hardware: the card keeps one small secret of its own, and from that secret and the key handle it works out the private key each time it is asked. So it needs almost no storage and can serve any number of passkeys, and the handle must be supplied for every use (OpenSSH, PROTOCOL.u2f, read 2026-11-11).

Two results follow.

- **The key handle is useless alone, and the card is useless without it.** The handle is no key. The card cannot find a passkey whose handle it is not given.
- **The site must know who you are first.** The standard says the site must manage the handle's storage and discovery, and be able to first identify the user in order to find the handle to supply (WebAuthn Level 3, "Server-side Public Key Credential Source").

The passkey that [ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/) uses is this second kind (the record: "the kind that stores nothing on the card"). The record does not say where the key handle is kept. The format of the wrapped key is fixed by the proof on a rehearsal card, and this page does not say where the key handle lives.

### What the PIN and the touch protect

The two are different checks, and the card says which it did. The answer is in the signed data as two flags: *user present* (the touch) and *user verified* (the PIN) (WebAuthn Level 3, section 6.1). The site decides whether it requires the PIN. If it does not, it ignores the second flag (section 7.2, verifying an assertion).

| | Shows | Does not show |
|---|---|---|
| **The touch** | Someone is at the card now, as for a PIV signature (see above). | Who it is, or which passkey it was for. |
| **The PIN** | The person knows the FIDO2 PIN. One PIN guards every passkey on the card. | Who the person is. It shows only that they know the PIN. |

What each protects, in a loss:

- **A thief with the card and no PIN** cannot sign in with a passkey that requires the PIN.
- **The same thief can still wipe the card (a FIDO reset needs no PIN),** so the PIN protects use, not existence.
- **After a reset the sites still hold your public keys, and nothing matches them.** Yubico says the card has to be registered again with every FIDO2 site, and with every U2F site too (Yubico FIDO page).

### How a sign-in works

ritueel signs in to no site. This list shows what the card does, so the next section can leave the site out.

1. **The site** sends a fresh random challenge. For a passkey not kept on the card, it also sends the key handle.
2. **The browser** checks the site name against the page's address, hashes the challenge together with that address, and hands the card the site name and the hash. *Result: the card never sees the address, only the site name.*
3. **You: the PIN,** if the site requires it. *Result: the card knows the person is verified.*
4. **You: the touch.** *Result: the card knows someone is present.*
5. **The card** finds the passkey, by site name or by the key handle, and signs with that passkey's private key. *Result: a signature leaves the card, and the private key does not.*
6. **The site** checks the challenge, the address, the hash of its own name, the two flags it needs, and the signature against the public key it saved. *Result: you are signed in. What crossed the network is useless later, because the next challenge is different. A fake site at another address would get a signature that the real site refuses.*

### A passkey that opens a key file

This is the use that ritueel's design rests on ([ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/)). There is no site and no signature. A program, not a browser, talks to the card over USB, and asks it for the secret of a passkey (see "A secret from a passkey" under Passkeys in brief).

ritueel locks key files with age, a small file-encryption format. A file can be locked to several recipients, each of which can open it alone. The key file has two: an **unlock key** and a recovery key. The private half of the unlock key is wrapped, and a passkey on each root card unwraps it. Any one root card of the pair is enough. The secret is not used on the file itself. It unwraps a second key, the unlock key, so that locking a new file needs no card.

1. **The program** reads the key file.
2. **The program** asks the card for the secret of its passkey, for a given input. The passkey is of the second kind, so a key handle has to be given to the card; where it is kept is not decided. *Result: the card waits for the PIN.*
3. **You: the PIN.** The record requires user verification. *Result: the card will answer.*
4. **You: the touch.** *Result: the card returns the secret, the same one each time for the same passkey and input.*
5. **The program** uses the secret to unwrap the private half of the unlock key, and opens the file with it. *Result: the key is in memory. The record says the unlock key's private half is in memory at each unlock.*

Writing a new key file needs no card, because the public half of the unlock key is a recipient. Browsers can do the same with the same standard, which they call PRF. ritueel does not unlock in its browser page, which runs on your own machine, because the browser would hand the secret to the page's script.

Other programs already use the extension this way. `systemd-cryptenroll` accepts FIDO2 tokens "that implement the ‘hmac-secret’ extension" to unlock a disk volume (systemd documentation). The age project's note describes a plug-in that reuses a passkey on a hardware token outside the browser, and a stanza that holds the file key wrapped with a key derived from the PRF output (published 2025-07-14). ritueel's own way (PIN and touch over USB from a static binary) is the part still to be proven.

**Decided, not yet proven.** [ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/#decided-not-yet-proven) words it so: a passkey secret with PIN and touch over USB from a static binary, and the offline system reaching the card's passkey side, are tried on a rehearsal card before anything is built (milestone M1). If the proof fails, a key-agreement key in PIV slot 9d of each root card opens the file instead, and nothing else in the record changes. The format of the wrapped key is fixed by the proof, so this page does not invent one.

**What the passkey does not remove.** A reset ends every passkey on the card, so the key file must also open another way. The record keeps a recovery key for this. If you lose the recovery key and both root cards, the key files cannot be opened. Without its key handle a card cannot rebuild the passkey, so the key handle is as important as the card; where it is kept is fixed by the proof.

## What each place is good for

| Job | Where | Why there |
|---|---|---|
| A root key (X.509 root or OpenPGP primary) | The root's row of the slot map: one slot for the X.509 root, one for the OpenPGP primary; PIN always, touch always | The card can vouch for the key, and the rules hold at every use ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/), [ADR 0016](/decisions/0016-several-bundles-share-one-pair-of-root-cards-and-the-bundle-keeps-a-card-inventory/#the-rows)) |
| Daily git signing and SSH sign-in | The OpenPGP application: a signing subkey and an authentication subkey | `gpg`, `git` and `ssh` use it without extra tools ([ADR 0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/)) |
| Opening the key file of a software key | A passkey of the kind the card does not keep, on each root card | The holder types a PIN and touches the card, and the file has no passphrase to lose ([ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/)); decided, not yet proven |

All three are designs, not built tools. For the same question asked of a cloud key, read [how a KMS key works](/learn/how-a-kms-key-works/).

## Sources

Read 2026-11-10, except the lines that say 2026-11-11.

- Yubico, [YubiKey 5 applications](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-index.html): applications are separate, with separate storage for keys.
- Yubico, [YubiKey 5 PIV](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-piv.html), [YubiKey 5 firmware 5.7](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-5.7.html) (key kinds, move and delete from 5.7.4, 100 passkeys from 5.7.4), [PIV certificate slots](https://developers.yubico.com/PIV/Introduction/Certificate_slots.html), [PIV admin access](https://developers.yubico.com/PIV/Introduction/Admin_access.html), [PIV PIN, PUK and management key](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-puk-mgmt-key.html), [PIV PIN and touch policies](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html), [PIV attestation](https://docs.yubico.com/yesdk/users-manual/application-piv/attestation.html) and [keeping track of keys](https://docs.yubico.com/yesdk/users-manual/application-piv/keeping-track.html) (the 5.3 metadata).
- Yubico, [YSA-2024-03](https://www.yubico.com/support/security-advisories/ysa-2024-03/): the ECDSA weakness (CVE-2024-45678).
- Yubico, [YubiKey 5 OpenPGP](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-openpgp.html): the three keys and their kinds; [OpenPGP attestation](https://developers.yubico.com/PGP/Attestation.html).
- Yubico, [YubiKey 5 FIDO](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-fido.html): PIN, tries, reset, deleting a passkey, nothing stored for a passkey not kept on the card, enterprise attestation from firmware 5.7. Read again 2026-11-11 for sign-in with no user name, and for registering again with every site after a reset. The page still says "up to 25 resident keys" (older text); the firmware 5.7 page gives 100 from firmware 5.7.4.
- Yubico, [hmac-secret deep dive](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/CTAP2_HMAC_Secret_Deep_Dive.html), [Developer's Guide to PRF](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html) (a lost authenticator means lost data) and [Securing WebAuthn with Attestation](https://developers.yubico.com/WebAuthn/Concepts/Securing_WebAuthn_with_Attestation.html).
- FIDO Alliance, [CTAP 2.2](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html): section 12.7 (hmac-secret) and section 6.6 (reset). ADR 0015 cites CTAP 2.1, section 12.5, for the same extension.
- W3C, [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/): the site name (relying party ID) and the credential. Read again 2026-11-11 for the public key credential source (its items, including otherUI), the server-side credential and "Relying Party Identifier" (section 4), authenticator data and its flags (section 6.1) and verifying an assertion (section 7.2: the UV flag is checked if user verification is required, and otherwise ignored).
- NIST, [SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html): syncable authenticators at the highest assurance level.
- OpenSSH, [PROTOCOL.u2f](https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL.u2f), read 2026-11-11: U2F hardware derives a private key from the key handle and a small secret of the device.
- The age project, [Encrypting Files with Passkeys and age](https://words.filippo.io/passkey-encryption/) (published 2025-07-14), read 2026-11-11: a token that returns the credential's state in the credential id, and an age plug-in that reuses a passkey on a hardware token outside the browser.
- systemd, [systemd-cryptenroll](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html), read 2026-11-11: FIDO2 tokens with the hmac-secret extension.
