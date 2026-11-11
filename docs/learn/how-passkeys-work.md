---
title: How passkeys work
description: What a passkey is, how a sign-in goes, what the PIN and the touch protect, and how a passkey on a card can open a key file.
---

*Design phase: ritueel is in design and has no release ([roadmap](/roadmap/)); nothing on this page is built. The facts were read on 2026-11-10 and again on 2026-11-11 in Yubico's documentation, in the FIDO and WebAuthn standards and in tool source, and nothing was measured on a card. Firmware numbers matter: a YubiKey 5 with older firmware does less.*

This page is the FIDO2 side of a YubiKey 5. Read [How a YubiKey holds keys](/learn/how-a-yubikey-holds-keys/) first: it shows what the card holds and how PIV and OpenPGP work. This page teaches what a passkey is, how a sign-in goes, what the PIN and the touch protect, and how a passkey on a card can open a key file. To see where passkeys sit among the places a root can live, read [choosing where a root lives](/learn/choosing-where-a-root-lives/).

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

**What the card says when a passkey is made.** Its attestation carries the model identifier (the AAGUID). Yubico states that a serial number is not shared (Securing WebAuthn with Attestation). With enterprise attestation, the serial number can be sent to a site that the card's list names: from firmware 5.7 (Yubico FIDO page). A FIDO reset turns it off again, and `ykman` turns it on. Compare [PIV](/learn/how-a-yubikey-holds-keys/#one-piv-slot-up-close): a PIV key's certificate names this card's serial number, and a passkey's names only the model.

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
| **The touch** | Someone is at the card now, as for [a PIV signature](/learn/how-a-yubikey-holds-keys/#how-a-piv-signature-happens). | Who it is, or which passkey it was for. |
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

Next: [how a KMS key works](/learn/how-a-kms-key-works/).

## Sources

Read 2026-11-10, except the lines that say 2026-11-11.

- Yubico, [YubiKey 5 firmware 5.7](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-5.7.html): 100 passkeys from firmware 5.7.4.
- Yubico, [YubiKey 5 FIDO](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-fido.html): PIN, tries, reset, deleting a passkey, nothing stored for a passkey not kept on the card, enterprise attestation from firmware 5.7. Read again 2026-11-11 for sign-in with no user name, and for registering again with every site after a reset. The page still says "up to 25 resident keys" (older text); the firmware 5.7 page gives 100 from firmware 5.7.4.
- Yubico, [hmac-secret deep dive](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/CTAP2_HMAC_Secret_Deep_Dive.html), [Developer's Guide to PRF](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html) (a lost authenticator means lost data) and [Securing WebAuthn with Attestation](https://developers.yubico.com/WebAuthn/Concepts/Securing_WebAuthn_with_Attestation.html).
- FIDO Alliance, [CTAP 2.2](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html): section 12.7 (hmac-secret) and section 6.6 (reset). ADR 0015 cites CTAP 2.1, section 12.5, for the same extension.
- W3C, [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/): the site name (relying party ID) and the credential. Read again 2026-11-11 for the public key credential source (its items, including otherUI), the server-side credential and "Relying Party Identifier" (section 4), authenticator data and its flags (section 6.1) and verifying an assertion (section 7.2: the UV flag is checked if user verification is required, and otherwise ignored).
- NIST, [SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html): syncable authenticators at the highest assurance level.
- OpenSSH, [PROTOCOL.u2f](https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL.u2f), read 2026-11-11: U2F hardware derives a private key from the key handle and a small secret of the device.
- The age project, [Encrypting Files with Passkeys and age](https://words.filippo.io/passkey-encryption/) (published 2025-07-14), read 2026-11-11: a token that returns the credential's state in the credential id, and an age plug-in that reuses a passkey on a hardware token outside the browser.
- systemd, [systemd-cryptenroll](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html), read 2026-11-11: FIDO2 tokens with the hmac-secret extension.
