# 0007 — ritueel teaches, and its tools simplify the ceremonies

**Status:** Accepted
**Date:** 2026-11-11

## Context

[0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/) made roots and their transitions a product, and named teaching as part of it. The maintainer sharpened the purpose on 2026-11-01: ritueel's goal is not to develop tools. It is to give people a smooth and safe experience of managing the root of a PKI and the master key of OpenPGP, including signing intermediates and subkeys, onto cards too.

The steps are mostly manual ceremonies, which is why there is a command line. Two facts follow. A reader who has never run a ceremony needs the logic before the tool, or the tool is a way to make an expensive mistake quickly. And a root lives for years, so the help has to cover the whole life: where the record lives, backup and restore, revocation, rotation and loss, not only the day a key is born.

## Decision

### The mission

> ritueel helps one person or a small team keep a private root and an OpenPGP primary key for years without losing it, leaking it, misusing it or letting it expire. It teaches the model first, and its tools run each ceremony with the person deciding.

**ritueel.id teaches first.** It explains the general logic of handling root keys and intermediates securely: what a root is, why it stays offline, what a ceremony is, the custody chain, the key stores compared, and the life of a root. The tools exist to simplify the rituals. The site is organised in that order: Learn, Guides, Tools, Reference, Decisions, Principles.

### Three faces of one engine

ritueel has three faces: the **command line**, a **guided mode** that asks line by line, and a **local page** served by the same binary on localhost, read-only ([0011](/decisions/0011-the-wizards-one-engine-three-faces-and-a-web-page-that-cannot-confirm-anything/)). Nothing is full-screen, and nothing is a service: one ritueel process serves the API behind all three faces, is started on demand, ends when idle, and serves the page only while it is in use ([0011](/decisions/0011-the-wizards-one-engine-three-faces-and-a-web-page-that-cannot-confirm-anything/)). All three are the same ceremony engine of [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/): plan, confirm, reserve, sign, verify, record. The guided mode and the page fill in flags and show the plan; neither is a second implementation (principle 6: a written contract, not parallel code). Both look good and keep the user in charge: nothing happens without the user's confirmation, and the PIN and the touch stay on the card.

### The wizard's security rules

These are the rules of the local page.

1. It binds to **127.0.0.1 only** and refuses any other address.
2. It listens on a **random port**.
3. It prints a **one-time token** in its address; a request without it is refused.
4. It checks the **Host and Origin** headers of every request, against DNS rebinding and cross-site requests.
5. It loads **no remote assets**.
6. It sends a **strict Content-Security-Policy**: its own files only.
7. **Every irreversible step is confirmed in the terminal or by touch,** never by a click alone. The page never receives a PIN, a passphrase or a key.
8. It sends no telemetry and makes no network call that a ceremony does not need.

### Software keys: three backends, all born in the store

A software key is generated in memory and written **directly into its store, never to disk**. The principle that a key is born in its store and never leaves it (principle 1) holds, because the store is the place where the key is written first. The software store has three backends:

| Backend | Role | Said plainly |
|---|---|---|
| Encrypted file | The default for drills and tests; opened as [0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-directory/) says. | A copy by nature. A backup is another copy. |
| 1Password, through its `op` command line | A persistent home for the software keys of **test roots, intermediates and subkeys**; never a production root or a person's master key. | Its sync gives redundancy against loss, not against compromise (principle 2). Whoever unlocks the vault has the key. |
| OS keyring, through `github.com/zalando/go-keyring` | Offered, with a warning in the creation output, in every record and on the site. | It can be insecure: programs of the same user can read it, and it has no copy. ritueel refuses to fall back to a file when no keyring exists. |

ritueel **never exports a key from a card or a cloud key** for backup. For cards, backup means two independent cards. For a cloud key, it means a replica that the service keeps. A software root remains unfit for a root that others rely on ([0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/)): it serves tests, drills, development and a person's own key.

### Key stores, compared in the open

The site compares the stores with what each protects against and what each costs: software and its backends, YubiKey (PIV and OpenPGP card) and AWS KMS today. **Google Cloud KMS, Azure Key Vault and other hardware such as Nitrokey are planned.** Each arrives with its first real installation, on a real account or a real device (principle 8), and not before. The site recommends which devices to buy for testing, with the date of each claim.

### An opinionated directory

The **directory** of [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/) is what the holder keeps; its write-once part, the **ledger**, holds the ceremony records. ritueel advises, and the guides say so plainly:

- It lives **in a git repository of its own,** with signed commits and review before a change lands, if the holder uses git; ritueel itself needs no git ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/)).
- It is **backed up** to a second remote on another provider, and the digest of the last record is kept apart from the repository.
- It holds public material, the sealed secrets of cards ([0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-directory/#card-secrets)) and the wrapped backup of a person's encryption subkey ([0017](/decisions/0017-a-persons-openpgp-key-in-two-stages-an-adopted-primary-first-then-card-born-primaries/#day-to-day-cards)). **Revocation certificates, the PINs a person types and passphrases are not in it.** The revocation certificates are kept apart from the cards, in at least two places.
- It is part of every key's identity, because it holds the OpenPGP creation times ([0003](/decisions/0003-key-stores-and-the-card-layer/)). Losing it is a loss; the backup is practised.

### The procedures ritueel will cover

Each procedure gets a page under Learn that says why and when, a guide that gives the steps, and a drill on test keys:

- **Backup and restore drills:** rebuild the state on a clean machine from the directory and the password manager, and compare it with the cards.
- **Revocation,** including **OpenPGP revocation certificates generated in advance** and kept apart, and CRLs and root lists for X.509.
- **Re-sign versus rotate** (principle 3): re-sign yearly, the same key with a new validity; rotate to a new key on an event, and a key in software also after at most three years.
- **Card loss and replacement.**

## Consequences

- The site is rebuilt around Learn. The old concepts pages are reorganised into Learn, Tools and Principles, and every old address redirects.
- The tools are held to a stricter bar: a feature that makes a ceremony faster but takes the decision from the person is refused.
- The local page is a security-critical component of its own: a read-only local web server in the same binary ([0011](/decisions/0011-the-wizards-one-engine-three-faces-and-a-web-page-that-cannot-confirm-anything/)). It needs its own tests and a security note in every pull request, but no second ceremony code.
- Two more software backends mean two more integrations to keep, and a platform matrix for the keyring.
- Pages must say what is built. The guided mode, the local page, the 1Password backend and the keyring backend are planned until their issues are done.
- Planned stores, and the hardware to buy for testing them, are written down before they exist. Each page dates its claims.

## Roads not taken

- **Tools first, and the teaching as an appendix.** Faster to build, but a reader who does not know why the root stays offline makes the expensive mistake faster.
- **A wizard with its own signing code.** A friendlier flow, but two implementations of the ceremony to test, and they will drift apart.
- **A desktop application instead of a localhost page.** No browser needed, but a large dependency, an installer to sign and a wider attack surface for the same screens.
- **A wizard reachable from other machines.** Shareable, but a network service that acts on root keys needs authentication and a larger attack surface ([0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)).
- **Only the encrypted file for software keys.** The simplest, but one copy on one disk, so a lost laptop loses the key.
- **1Password as the home of a production root or a person's master key.** A synced copy that survives a lost laptop, but whoever unlocks the vault has the key, and removing a member of a shared vault does not change its keys ([research](/research/software-key-backends-2026-11-01/)); it holds test keys, and the master key of a person is a file ([0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/)).
- **Importing a key into 1Password or the keyring.** Lets people bring an old key, but the key then existed outside its store, which principle 1 rules out.
- **Exporting a key from a card or KMS for backup.** An easy restore, but it turns a key that cannot be copied into one that can, and the theft risk grows with every copy.
- **The OS keyring as the default.** No account and no setup, but it is the weakest option, so ritueel offers it with a warning and does not choose it for the user.
- **Google Cloud KMS, Azure Key Vault and Nitrokey in the first version.** Wider reach, but every store multiplies tests and guides and none has an installation to prove it.
- **A hosted ledger.** Nothing for the holder to back up, but a service that every ceremony trusts, and ritueel has none.

## Follow-ups

- The local page and the guided mode ([#17](https://github.com/truvity/ritueel/issues/17), [#16](https://github.com/truvity/ritueel/issues/16)).
- The 1Password store ([#59](https://github.com/truvity/ritueel/issues/59)).
- The OS-keyring store ([#60](https://github.com/truvity/ritueel/issues/60)).
- The drills, including the restore drill ([#20](https://github.com/truvity/ritueel/issues/20)).
- The revocation certificates made at birth, and the adoption drill ([#48](https://github.com/truvity/ritueel/issues/48)).
