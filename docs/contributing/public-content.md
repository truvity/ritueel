---
title: Public content and secrets
description: What may appear in the public ritueel repository, which example names to use instead of real ones, and how secrets, keys and test hardware are handled.
sidebar:
  order: 8
---

This repository is public, and so is everything around it: code, docs, the CHANGELOG, tests, test data, commit messages, issues and pull requests.

## Use example names

Nothing names a real organisation account, hostname, cluster, ticket, secret path, customer, private installation or person other than the maintainer. Write the example instead:

| Instead of a real | Write |
|---|---|
| domain or hostname | `example.com`, `ca.example.com` |
| organisation or company | `acme`, `globex` |
| IP address | an address from the documentation ranges: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32` |
| cloud account id | `123456789012` |
| key id, fingerprint or serial number | an obviously made-up value, or `<fingerprint>` |
| ticket or issue key of an internal tracker | nothing; link a public issue of this repository instead |
| person | a role: "the holder", "the operator", "the relying party" |

Internal reasoning that needs real names stays internal; only the final, generic text is public ([GOVERNANCE.md](https://github.com/truvity/ritueel/blob/main/GOVERNANCE.md), "From internal reasoning to a public ADR").

CI scans every tracked text file for content that must not be public, such as account-id-shaped numbers, private key blocks and token prefixes (`just check-public`). Maintainers run additional checks before merging. A pass is not permission: the rule above is.

## Secrets and key material

- Never print a secret, a PIN, a passphrase or a token: not in a terminal you share, a log, a test fixture, a commit, an issue or a pull request. Use test values.
- Never commit private key material, not even a throw-away key, unless it is a clearly marked test fixture generated for the test and the maintainer has agreed. Public keys, certificates and fingerprints of test keys are fine.
- If a secret was printed or pushed anyway, tell the maintainer at once.

## Vulnerabilities

A suspected vulnerability goes through [SECURITY.md](https://github.com/truvity/ritueel/blob/main/SECURITY.md), privately. Never open an issue, a pull request or a discussion for it.

## Hardware tokens

A test device's serial number is not written into the repository. How tests use hardware tokens is in [Hardware tokens and cloud keys](/contributing/tools/#hardware-tokens-and-cloud-keys).
