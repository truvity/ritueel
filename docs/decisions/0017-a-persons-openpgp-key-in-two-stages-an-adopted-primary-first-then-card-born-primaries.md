# 0017 — A person's OpenPGP key in two stages: an adopted primary first, then card-born primaries

**Status:** Accepted
**Date:** 2026-11-11

## Context

[0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/) makes a person's primary a new certify-only P-384 key, born in a software key file, offline. It says a primary on a card "is not served" and that the first version has no encryption subkey. [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#keys) and [principle 1](/principles/) say nothing is imported.

A person who comes to ritueel may already have a primary with years of certifications, and a new primary costs every contact a new certification (0012, "How long a person's primary lives"). A person also needs to decrypt mail, and mail encrypted to a card-born key is lost with the card (0012, Consequences).

This record makes one stated exception to "nothing is imported", on purpose, for a person's own key only: an existing primary adopted as a software key. It also changes one rule of 0012 for a person's own key: the first version now has an encryption subkey. A staff key ([0014](/decisions/0014-staff-openpgp-primaries-sealed-in-sluis-subkeys-born-on-cards-ritueel-makes-the-card-ready-and-runs-the-delegation/)) is unchanged. The proposal is the design round of 2026-11-10 and 11, tracked in the issues under Follow-ups.

## Decision

### Stage one

- **An existing primary may be adopted as it is, with its history,** as a software key in a key file opened as [0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-directory/) says. This is the one stated exception to "nothing is imported".
- **The key is marked adopted in its record.** It may be RSA-4096 and without expiry on arrival. It gets an expiry at adoption.
- **It is replaced within three years of adoption,** or moved to stage two. The rule of 0012, "How long a person's primary lives", runs from the adoption.

### Stage two

- **Two card-born primaries, one on each root card,** in the personal root's row ([0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/#the-rows)). One is published. The other is a standby, and the published one certifies it.
- **The old key vouches for the published one, with an overlap, and then ends** ([0009](/decisions/0009-root-transitions-vouch-overlap-retire-and-revoke/)).

### Day-to-day cards

- **A signing subkey and an authentication subkey are born on each day-to-day card,** one set per card.
- **An encryption subkey is made in software, loaded onto each day-to-day card, and kept in a wrapped backup in the directory.** This overrides "no encryption subkey in the first version" of 0012 for a person's own key. The reason: a lost card must not lose the mail it decrypted, so this key cannot be card-born.
- **The format and the command** for the encryption subkey are fixed with stage one.
- **The touch setting of each key is the holder's choice.** The guide says what each choice costs.

### Retiring a subkey

- **A subkey that is replaced is retired by a revocation with the reason "superseded",** dated on the day of the switch, or by expiry. "Compromised" is for compromise only ([0010](/decisions/0010-readiness-is-made-at-birth-and-proved-by-a-drill/#revocation-material)).
- **What verifiers do with the signatures of a retired subkey** was measured on 2026-11-10 and is in [the research note](/research/openpgp-subkey-retirement-2026-11-10/). This record cites it and does not repeat it.

## Consequences

- Principle 1 and the pages that cite it read with one stated exception, for a person's own key only.
- An adopted RSA primary is outside the P-384 profile of the hand-off contract and of 0012. [The personal reference](/reference/personal-openpgp/) says what ritueel does with it.
- A person's encryption key exists in software and in a wrapped backup, so it can be copied. The records and the guide say so.
- A tag signed by a retired or expired subkey may no longer verify with `git verify-tag` (see the research note), and how to check old tags is not yet measured. The guide says so.
- The standby primary is a second card-born key to certify and to store apart.
- Stage two is decided and not built. It depends on [0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/) and on the card proofs.

## Roads not taken

- **Make a new primary at once and drop the old one.** Nothing is imported, but every contact certifies again and the history is lost.
- **Adopt the key and keep it forever, with no expiry.** The least work, but a copyable key with no end is what the three-year rule exists to prevent.
- **A software primary only, with no stage two.** One stage, but the primary stays copyable for good; 0012 weighed the card (no backup) and the standby answers that.
- **One card-born primary on one card.** The key cannot be copied, but a lost card is a lost identity (0012); two primaries, one certifying the other, answer that.
- **The old key certifies both new primaries.** One step fewer, but the standby would then depend on the old key that is going away.
- **An encryption subkey born on each card.** Nothing is imported, but a lost card loses the mail it decrypted.
- **An encryption key kept only in a file, not on the cards.** No copy on a card, but every decryption needs the file opened.
- **Retire a replaced subkey as "compromised".** The simplest wording, but it states a compromise that did not happen, and the research note shows verifiers treat it more harshly than "superseded".

## Follow-ups

- Stage one: the adoption command, the expiry at adoption, the day-to-day subkeys, the software encryption subkey with its wrapped backup, and the guide that states what each touch setting costs ([#18](https://github.com/truvity/ritueel/issues/18)).
- Stage two on the root cards, after the card proofs ([#11](https://github.com/truvity/ritueel/issues/11)).
