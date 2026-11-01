---
title: Design principles
description: What ritueel is and is not, and the rules its design follows. Some are shared with systems that hold intermediates, some are ritueel only, some do not apply.
sidebar:
  order: 1
---

*Design phase: these are the principles the design follows today. Each links to the record or page that decides it. Principles 1 to 11 carry the same numbers as in [sluis](https://sluis.id), a system that holds intermediates; ritueel's own start at 12.*

## What ritueel is, and is not

- **A command-line tool and documentation, not a network service.** It holds no online keys. See [ADR 0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/).
- **It owns roots, root ceremonies and root transitions** for X.509, OpenPGP and SSH CA key lists, personal OpenPGP keys included. See [ADR 0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/) and [ADR 0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/).
- **It never holds an intermediate's private key.** Systems like [sluis](https://sluis.id) hold intermediates, and meet ritueel only through the [hand-off contract](/reference/hand-off-contract/).
- **Its records are files the operator keeps:** ceremony records, root lists, and keyring packages that ritueel builds and the user's own pipeline publishes. See [ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#the-directory-and-the-records) and [ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/).

## Shared with systems that hold intermediates

1. **Every key is born in its store and never leaves it.** A transition makes a new key, and the old one vouches for it. See [ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/) and [Roots, intermediates and transitions](/concepts/roots-and-transitions/).
2. **Trust is layered, and redundancy answers loss, not compromise.** There are two root cards because a card cannot be copied, and one KMS root plus a replica because KMS can replicate its key. A compromise is answered by revocation and a transition. See [ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#keys) and [Two roots in practice](/concepts/two-roots/).
3. **Keys are shared and rotated by rule.** A key is shared only where audience, lifetime, revocation coupling and callers are all equal, as for the X.509 root key that also signs the root list. Renewal re-signs; key material is replaced on an event or at most every three years, and a transition makes a new key, never a copy. See [the slot map](/decisions/0003-key-stores-and-the-card-layer/#the-piv-store-and-the-root-cards) and [renewal and replacement](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#validity-renewal-and-replacement).
4. **Verify; never trust a claim.** Attest what can be attested, re-read KMS keys and their policies from the service, and accept no copy of either. A check that cannot run is reported as not run, never as passed. See [What the tool checks](/concepts/ceremonies/#what-the-tool-checks) and [the proof file](/reference/hand-off-contract/#the-proof-file).
5. **Open standards, as their consumers implement them.** OpenPGP keys are version 4 while `gpg` has no version 6, and a revoked key leaves the keyring package because `gpgv` ignores revocations. See [ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#the-keys).
6. **A written contract and test vectors, not shared code; things are named for what they are.** The word is `intermediate`, not the name of a device. See the [hand-off contract](/reference/hand-off-contract/) and its [test vectors](/reference/hand-off-contract/#test-vectors).
7. **A person only where a person adds safety.** A touch on a card and a typed digest of the plan need a person; routine work reads public files only and is automated. See [ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#six-steps-every-ceremony) and [The ceremony](/concepts/ceremonies/).
8. **Nothing without a consumer.** During design, a record is rewritten in place and not extended by amendments. See the [roadmap](/roadmap/) and [how decisions are made](/contributing/decisions/).
9. **Measure, and date the measurement.** A claim about a tool, a card or a service carries the day it was measured. See [the research pages](/research/).

*Principle 10 of sluis is particular to sluis; see [Not applicable to ritueel](/concepts/principles/#not-applicable-to-ritueel).*

11. **Public by default, private where it protects.** The design, the reasons and the roads not taken are public; secrets and private deployment details are not. See [Public content and secrets](/contributing/public-content/).

## Particular to ritueel

12. **Roots are offline and rare, but not air-gapped.** A ceremony runs on an ordinary workstation, because the key never leaves its card or KMS; the checks exist because that workstation can still lie about what is signed. See [ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#the-yearly-ceremony).
13. **One ceremony, many key stores:** software, PIV, OpenPGP card and AWS KMS. Only the store and the key's consumer differ, and each store is proven on real hardware or a real account. See [ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#four-stores-behind-one-interface) and [Where a key lives](/concepts/key-stores/).
14. **ritueel is a teaching product.** Every ceremony is explained, every road not taken is recorded, and a guide walks through each transition. See [ADR 0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/) and [A lost root card](/guides/lost-root-card/).

## Not applicable to ritueel

Principle 10 of sluis, one product in many installation shapes, has no counterpart: ritueel is a command-line tool and documentation, not a running service. Nor do reference installations with tenants, an audit record format, or serverless and Kubernetes runtimes apply. Its record is the ceremony record of [ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#the-directory-and-the-records).
