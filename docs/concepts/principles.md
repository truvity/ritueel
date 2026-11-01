---
title: Design principles
description: The rules ritueel's design follows, from where a key is born to what is public, each in a sentence or two with the records and pages that follow from it.
sidebar:
  order: 6
---

*Design phase: these principles are the ones the design follows today. They are shared with other systems that hold intermediates; each is decided in a record or a page that the link names. Dates are the day a measurement or a decision was made.*

1. **Every key is born in its store and never leaves it.** A transition makes a new key, and the old one vouches for it; nothing is exported or imported. See [ADR 0002](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/) and [Roots, intermediates and transitions](/concepts/roots-and-transitions/).

2. **Trust is layered, and redundancy answers loss, not compromise.** Roots stay offline, intermediates are re-signed yearly, and key material is replaced only on an event or at most every 3 years. There are two root cards because a card cannot be copied, and one KMS root plus a replica because KMS can replicate its key. A compromise is answered by revocation and a transition. See [Renewal and replacement](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/#renewal-and-replacement) and [Two roots in practice](/concepts/two-roots/).

3. **One key, one purpose.** Keys are shared only where audience, lifetime, revocation coupling and callers are all equal and the store itself separates the uses. See [the slot map](/decisions/0003-ceremonies-plan-confirm-reserve-sign-record-and-the-ritueel-commands/#the-slot-map-of-a-root-card) and the [hand-off contract](/reference/hand-off-contract/), where a key that signs tokens is kept apart from an intermediate.

4. **Verify; never trust a claim.** Attest what can be attested, re-read KMS keys and their policies from the service, and accept no copy of either. A check that cannot run is reported as not run, and never as passed. See [What the tool checks](/concepts/ceremonies/#what-the-tool-checks) and [the proof file](/reference/hand-off-contract/#the-proof-file).

5. **Open standards, as their consumers actually implement them.** OpenPGP keys are version 4 while `gpg` has no version 6, and a revoked key leaves the keyring package because `gpgv` ignores revocations. See [ADR 0004](/decisions/0004-release-keys-primaries-on-the-roots-signing-subkeys-and-the-keyring-package/#algorithm) and [OpenPGP release keys](/concepts/openpgp-release-keys/#revocation).

6. **Generic products, joined by a written contract and test vectors, not by shared code.** Things are named for what they are: `intermediate`, not `board`. See [ADR 0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/) and the [hand-off contract](/reference/hand-off-contract/).

7. **A person only where a person adds safety.** A touch on a card and a typed digest of the plan need a person; routine work is automated. See [ADR 0003](/decisions/0003-ceremonies-plan-confirm-reserve-sign-record-and-the-ritueel-commands/) and [The ceremony](/concepts/ceremonies/).

8. **Nothing without a consumer; during design, rewrite rather than accumulate.** A feature waits for something that uses it, and a record that is still in design is rewritten in place, not extended by amendments. See the [roadmap](/roadmap/) and [how decisions are made](/contributing/decisions/).

9. **Measure before deciding, and date the measurement.** A claim about a tool, a card or a service carries the day it was measured, and is checked again before it is relied on. See [what was tested](/concepts/openpgp-release-keys/#what-was-tested).

10. **One ceremony, many key stores.** The ceremony makes or binds a key; only the store (`software`, `piv`, `openpgp-card`, `aws-kms`) and the key's consumer differ. Each store is proven on real hardware or a real account. See [Key stores](/decisions/0003-ceremonies-plan-confirm-reserve-sign-record-and-the-ritueel-commands/#key-stores-one-ceremony-many-stores) and [Where a key lives](/concepts/key-stores/).

11. **Public by default, private where it protects; ritueel is a teaching product.** The design, the reasons and the roads not taken are public, and no secret or private deployment detail is. See [Public content and secrets](/contributing/public-content/) and [ADR 0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/).
