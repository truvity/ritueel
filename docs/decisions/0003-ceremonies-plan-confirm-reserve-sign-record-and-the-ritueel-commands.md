# 0003 — Ceremonies: plan, confirm, reserve, sign, record; and the ritueel commands

**Status:** Proposed
**Date:** 2026-11-01

Proposal: [issue #27](https://github.com/truvity/ritueel/issues/27). The commands are built in [issue #30](https://github.com/truvity/ritueel/issues/30), the records in [issue #9](https://github.com/truvity/ritueel/issues/9), the transitions in [issue #13](https://github.com/truvity/ritueel/issues/13), and the software-root mode in [issue #8](https://github.com/truvity/ritueel/issues/8). The record stays `Proposed` while the open parts at the end are undecided; they are tracked in issues #26 and #27.

## Context

[0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/) says what ritueel owns, and [0002](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/) fixes the model: every key is born in its store, there are two independent roots, one holder, and the root of the year signs. This record says how a person uses that model: which commands exist, what every ceremony does, what it checks before it touches a root, what it writes down, and how it behaves without a person at hand, in tests.

Four facts shape it.

- **A root is used with a person present, and rarely.** A mistake costs a year or a trust update. The command has to show what it is about to sign in a form the person can compare, and it must not be possible to confirm by habit.
- **The workstation is ordinary.** There is no air gap, so the tool cannot assume the machine is clean. The key never leaves its store, so the machine cannot copy it, but it can lie about what is being signed. The checks exist for that.
- **A card forgives little.** After three wrong PINs a card blocks and needs the PUK. A missed touch comes back about 15 seconds later as a generic security status, not as a touch timeout (measured 2026-10-31 on a YubiKey 5, firmware 5.8.0).
- **The first consumer has no hardware.** A system that needs a certified intermediate on day one, and its test harness, need a software root that a script can drive. The same commands have to serve both.

## Decision

### The commands

| Command | Does | Needs a person |
|---|---|---|
| `ritueel init` | Creates the directory, the roots (`--roots N`, default 2, both cards present) and their revocation material, and the first trust products. | Yes |
| `ritueel yearly` | The yearly ceremony: certifies every pending request with the root of the year, and publishes the next trust sequence. | Yes |
| `ritueel board add NAME` | Registers a system that holds intermediates and certifies its first request. | Yes |
| `ritueel board replace NAME` | Certifies a new key for a registered system. `--revoke` also revokes the old one, with a reason. | Yes |
| `ritueel root add` | Creates a new root in a store, and has an existing root vouch for it. This starts an overlap. | Yes |
| `ritueel root retire ROOT` | Ends an overlap: removes the root from the next trust products. | Yes |
| `ritueel root revoke ROOT` | Revokes a lost, stolen or compromised root. | Yes |
| `ritueel status` | Lists roots, intermediates and unresolved attempts, with what expires when. | No |
| `ritueel handoff check REQUEST` | Runs every check of the [hand-off contract](https://github.com/truvity/ritueel/blob/main/docs/reference/hand-off-contract.md) on a request and signs nothing. | No |
| `ritueel bundle build`, `ritueel keyring build` | Build the CA bundle and the keyring packages from the directory. | No |
| `ritueel records list`, `ritueel records verify` | Read the ceremony records and check their chain. | No |
| `ritueel wizard` | A guided front end to the commands above. | Yes |

The verbs of a transition ([13](https://github.com/truvity/ritueel/issues/13)) map onto the commands: *create* and *vouch* are `root add`, *overlap* is a state that both roots are in and not a command, *supersede* is `root retire`, and *revoke* is `root revoke`. `board` is the word of 0002 for a system that holds intermediates; whether to use a more general word is open.

Routine work needs no person and no card, because it reads public files only. `bundle build` and `keyring build` give the same bytes from the same directory, so a pipeline can run them on every change and publish the result.

### Every ceremony has the same six steps

1. **Plan.** Reads the directory and the pending requests, and writes a plan: a file with every byte that will be signed fixed in advance. It holds the chosen root, each key's fingerprint, store and (for a YubiKey) serial, every certificate serial number, every validity and signature time, and the number of touches. **Serial numbers and times are drawn here, once**, so the exact bytes can be recomputed by anyone before the touch. The plan needs no card, so it can be made on any machine, and it holds public information only.
2. **Confirm.** Shows the plan in words and prints its digest. The person confirms by **typing the first eight characters of the digest**. A key press is not accepted, because it can be pressed without looking. A script confirms with `--confirm DIGEST`, so it must compute the digest first and cannot confirm a plan it has not read. A confirmation never replaces a touch on a card.
3. **Reserve.** Before the first signature, writes an *attempt* to the directory: the plan digest, the root and the time. If the run stops after the card has signed, the attempt shows that signatures may exist and that its serial numbers are used. The next run starts from a new plan; `status` lists the attempt until a person closes it with `records close`.
4. **Sign.** Uses the root. Shows each fingerprint before the touch.
5. **Verify.** Checks every artifact against its request and the plan, with code that did not sign it, before it is written to the output directory: the certificate chain, and for OpenPGP the binding.
6. **Record.** Writes the ceremony record and the transcript, and then the trust products.

A command runs all six in one go (`ritueel yearly`). `--plan-only` stops after step 1 and writes the plan. `--plan FILE` runs steps 2 to 6 from a plan made earlier, after checking that it still matches the directory. So a ceremony is one command, or two when the person wants to review the plan first, or three when someone else reviews the plan on another machine. Publishing the result is the user's pipeline.

### What is refused before anything is written

- A card whose serial is not in the registry, or is the wrong card for the role (root A for the year of B).
- A fingerprint that differs from the one in the plan, or from the one the requester printed.
- A key that cannot be attested when the policy asks for attestation (an imported key cannot).
- A collision in the slot map, or a purpose that has no slot.
- A card whose PIN retry counter is below three. ritueel **never retries a PIN**, and never reads one from an argument or the environment; the holder types it at the terminal, which does not echo.
- A card with a default PIN, PUK or management key, at `init`. The holder sets them first.
- A request that fails a check of the hand-off contract.

### The slot map of a root card

The slot map is a table inside ritueel with a version number, not a file the holder edits. It gives each purpose one place on the card and refuses two purposes in one place. Version 1:

| Purpose | Place |
|---|---|
| X.509 root key | PIV slot 9c |
| OpenPGP primary | Open: see the card layer below |
| Root list signing | Not assigned: it follows [issue #14](https://github.com/truvity/ritueel/issues/14) |

The version in use is written in every record. A holder who edits slots by hand is outside the design; ritueel then refuses, because a slot it did not reserve is occupied.

### The directory

ritueel keeps its state in one directory of plain files, which holds **public material only**: the configuration, the registry of known cards, the roots' certificates and public keys, the revocation certificates' digests, the plans, the ceremony records and transcripts, and the trust products. A private key, a PIN, a passphrase and a revocation certificate itself are never in it. The directory is meant to be kept in version control by the holder, and it must be backed up: the creation time of an OpenPGP key is part of its fingerprint and is not on a card.

The registry holds, for each known card, the serial, its role and the fingerprints of the keys made on it. It is filled by `init` and `board add`. The directory is chosen with `--dir`, and defaults to the current directory when it holds `ritueel.yaml`.

### Records and transcripts

- Each ceremony writes one record: a JSON file with the date and time in UTC, the command, the plan digest, the roots and keys involved (fingerprints, store, and the serial or key ARN as the holder chooses to keep it), the evidence checked, the policy applied, the artifacts with digests, the slot map version, and the confirmation. It holds no PIN, passphrase or key.
- **Records form a hash chain:** each holds the digest of the one before. `records verify` checks the chain, and a modified record breaks it.
- **Records are not signed by a root.** A root signs certificates, bindings and root lists; signing records with it means a third kind of use and one more touch. The digest of the last record goes into every root list the ceremony signs, so the chain is anchored in a signed artifact without a separate signature. A holder is advised to commit the directory with signed commits.
- **The transcript is what ritueel printed**, written by ritueel itself. It is not a capture of the terminal, because a capture can hold what was typed. The record holds its digest.

### Who signs, and when

- The root of the year signs a yearly ceremony. The default is the root that did not sign the previous yearly ceremony, found in the records. `--root` overrides it, and the reason is recorded. If a root is retired or revoked, the other signs.
- **When.** Intermediates last 13 calendar months. The yearly ceremony is held in month 12 of their life, when the earliest expiry is 60 to 30 days away. `status` warns at 60, 30 and 14 days (configurable), the same days a system that holds intermediates warns on its side; its exit code is 0, 10, 11 or 12 for nothing due, notice, alert and critical.
- **Pending requests.** `yearly` takes one request for every registered system. It stops when one is missing, because that system would then expire, unless the person passes `--allow-missing NAME`, which is recorded.

### Revocation readiness

- When a root is born, `init` makes a **revocation signature** for its OpenPGP primary, and the person stores it apart from the card. Its digest goes into the record.
- OpenPGP offers two ways to let another key revoke: the *Revocation Key* subpacket (the designated revoker), and an escrowed revocation signature. RFC 9580 (section 5.2.3.23) deprecates the first: applications **must not generate** it, and calls the second preferred (section 13.9). 0002 asks for designated revokers. This record proposes to keep the escrowed signature as the mechanism, and to treat the designated revoker as a legacy extra to be tested, not generated. See the open parts.
- **X.509.** `root revoke` signs a root list without the root, with the surviving root. Clients that fetch the list stop trusting it. A CRL for the intermediates a revoked root issued is produced by the surviving root.
- The test that `gpg`, `gpgv`, `sqv`, apt and rpm honour a pre-made revocation certificate runs before a guide claims it ([issue #24](https://github.com/truvity/ritueel/issues/24)).

### Cards and a missed touch

- The card is selected by serial. A test never takes "the first card".
- A touch not given comes back as a generic security status after about 15 seconds. ritueel reports **"the card refused after N seconds: no touch was given in time, or the PIN state was lost"** when the PIN was accepted in the same session and the refusal came after 10 seconds or more. It claims no more than it knows, and it does not retry. It reports a refusal that came sooner as a refusal.
- Reading a PIN, checking counters and unlocking happen in ritueel's card layer, never in a script around it.

### The software root, and tests

- Software mode runs the same commands and the same six steps. Its root is a passphrase-protected file. The first output of `init`, every confirmation and every record say that **a software root can be copied**.
- A script drives it with `--passphrase-fd N` and `--confirm DIGEST`. For a test harness there is `--test-root`, which makes a root with no passphrase. A test root is marked in its certificate name (`TEST ONLY`) and in every record, and `bundle build` and `keyring build` **refuse to put a test root and a real root in the same product**, so a development root cannot ship by mistake.
- The software root is the first store that exists, and the first consumer of ritueel depends on it.
- A test that needs hardware is tagged, skipped by default, selects its card by serial from the environment, and resets the card when it ends.

### KMS roots

A KMS root follows the same steps. The confirmation is the typed digest plus a role that needs multi-factor authentication; ritueel uses the credentials of the caller's standard chain and stores none. The record holds the key ARN, the digest of the key policy and the role session. The company model is one KMS root with a replica in a second Region. A replica of a multi-Region key is the same key, so it adds availability and not independence; whether that is enough is open.

### Wizards

The CLI wizard and the web wizard ([16](https://github.com/truvity/ritueel/issues/16), [17](https://github.com/truvity/ritueel/issues/17)) only fill in the flags and show the plan. They hold no logic and no state of their own. The web wizard listens on `127.0.0.1` on a random port with a per-session token, and has no option to listen elsewhere.

### Exit codes

0 success; 1 failure; 2 usage; 3 refused by a check or by the policy; 4 refused by the card or its PIN state; 5 not confirmed; 10 to 12 only from `status`.

### The accepted limit

`init` prints it, and the record says it was shown: whoever holds one root card and its PIN can sign things that outsiders trust, until that root is revoked and the update reaches them. A stolen card without its PIN locks after three tries.

### Open

- **The card layer** ([issue #26](https://github.com/truvity/ritueel/issues/26)). The options are below. **Recommendation: A.**

  | | Option | Pros | Cons |
  |---|---|---|---|
  | A | Go with a PIV library (go-piv/piv-go v2.6.0, Apache-2.0, released 2026-04-15, bundles the maker's current attestation root); **both root keys in PIV slots**: the X.509 root in 9c and the OpenPGP primary in a retired slot; ritueel builds the OpenPGP packets and the card signs digests | One applet, one library, one binary, no `gpg`, no second language. Attestation works the same for both keys. The spike showed a PIV key makes back-signatures that `gpg`, `gpgv` and `sqv` accept (2026-10-31). | The OpenPGP applet of the card stays unused, so `gpg --card-status` shows nothing. The primary's certification and binding signatures by a PIV key are the same operation but were not yet tested. The key's creation time is not on the card. It changes issue #11, which names the OpenPGP applet. |
  | B | Go with PIV for X.509 and ritueel's own code over PC/SC for the OpenPGP applet | Keeps the OpenPGP applet in use. | The PC/SC binding for Go that is most used (`ebfe/scard`) was last pushed on 2024-12-14; applet code to write and keep. |
  | C | Go builds the packets and uses `gpg-agent` only as the card signer | Works today (595 lines in the spike). | Needs `gpg`, `gpg-agent` and `scdaemon` at run time; `gpg` 2.2 sent two wrong PINs to a test card. |
  | D | A Rust helper (`openpgp-card` with rPGP) | Did every step in the spike (340 lines). | A second language and a helper to package and sign, for key handling that no longer keeps a key in memory. |

- **Root expiry.** Options: none; about three years, extended at each use; fixed ten years with expiry treated as a scheduled transition. *None*: no churn, no signal of a root nobody uses. *Three years, extended*: a dead card shows itself, but the root certificate changes each year, so CA bundles change each year and a client that pins the certificate breaks. *Ten years*: stable, the expiry is a plan, and `status` warns at 12, 6 and 3 months. **Recommendation: ten years, no extension.**
- **The designated revoker.** Amend 0002 to drop the *Revocation Key* subpacket, as RFC 9580 requires, and keep the escrowed revocation signature. Pro: the standard's own route. Con: the holder must store the escrowed signature apart from the card, and it can be lost.
- **`board`**, the name of a system that holds intermediates in the commands. Options: keep it (0002 uses it); use a general word such as `holder`. Keeping is cheaper now; the general word is clearer in a generic product.
- **Lifetimes.** Settled: 13 calendar months for intermediates, ceremony in month 12, warnings at 60, 30 and 14 days. Not settled here: the lifetime of the signed root list ([issue #14](https://github.com/truvity/ritueel/issues/14)) and the PIV touch policy of the root key (always, as 0002 says, or cached).

## Consequences

- A ceremony is reviewable: the plan can be read, hashed and checked by someone else before a card is touched, and the same plan produces the same bytes.
- A script cannot confirm a plan it has not computed the digest of, yet a test harness can still drive every command without hardware.
- A crash after the first signature leaves a record of it. The cost is a step, `records close`, that a person must take.
- Writing the plan and the record is code that exists only for the ceremony. In return, there is one shape to test, teach and check.
- The directory is the holder's to back up. Losing it loses the registry and the fingerprints' creation times; the published keyring and root list still hold the public material.
- If option A of the card layer wins, there is one card library to keep up and no OpenPGP applet code, and the OpenPGP tests of 2026-10-31 must be extended to the primary's own signatures.
- Typing a digest prefix per ceremony is slower than pressing a key, by a few seconds, once a year.
- The touches per ceremony grow with the number of systems; the plan prints the count.

## Roads not taken

### One command with no plan step

- Pros: simpler to build and to explain.
- Cons: nothing to review before the touch; serial numbers drawn at signing time cannot be checked in advance; a crash leaves no trace of what may have been signed.
- Why not: the plan and the reservation are the two features that make a once-a-year ceremony safe to do from memory.

### Confirm by pressing a key

- Pros: fast and familiar.
- Cons: it is pressed without reading; it cannot be driven by a script in a way that proves the script read the plan.
- Why not: typing a prefix of the digest costs seconds and forces a comparison.

### Sign each record with the root

- Pros: a third party who knows the root can check a record.
- Cons: a third use of the root and one more touch; a root key signs data that is not a certificate, binding or list.
- Why not: the chain, anchored in the signed root list, gives most of the value. A separate record-signing key is an option for later.

### Capture the terminal as the transcript

- Pros: complete, no code.
- Cons: it can hold what was typed, including a PIN if echo is ever wrong; it is hard to test for secrets.
- Why not: ritueel prints no secret, so what it writes itself is safe to keep.

### A slot map the holder edits

- Pros: flexible; fits an odd card.
- Cons: two purposes in one slot, or a purpose with no slot, becomes a user error that overwrites a key.
- Why not: a built-in, versioned table makes the collision impossible and is recorded in each record.

### `init` creates one root at a time

- Pros: the second card can stay in its other place.
- Cons: the OpenPGP revocation material and the root list of two roots are made together; a one-root first run leaves a state that the model calls unsafe.
- Why not: `init` has both cards present once, and they go to their two places afterwards. A single software root, for a test, is `--roots 1`.

### Keep a ceremony service running

- Pros: a web interface for several people.
- Cons: a network service that holds ceremony state and acts on roots.
- Why not: [0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/) keeps the wizard on localhost, and a ceremony is one person at one machine.
