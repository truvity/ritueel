---
title: Leaf keys under your intermediate
description: What a team may choose for the keys and certificates it issues under a ritueel intermediate, and what the intermediate already fixes. Advice, not a rule.
sidebar:
  order: 14
---

*Advice, not a rule of ritueel. ritueel signs the root and the intermediate; it issues no leaf, and no ritueel command is used on this page. Every sentence is a choice for the team that runs the issuing system, and none binds anyone. Sources are numbered and listed at the end; they were read on 2026-11-13.*

A **leaf** is the end of the chain: the certificate of a server, a service or a client. Your issuing system holds the intermediate's key and makes the leaves ([Private PKI](/learn/chain-private-pki/)). This page says what the intermediate already fixes for a leaf, and what is left to you.

## What the intermediate fixes

- **Time.** An intermediate's certificate lasts 13 calendar months ([the contract](/reference/hand-off-contract/)). No chain is valid longer, and AWS Private CA, for one, refuses to issue a leaf that would outlive its parent [1].
- **Names.** The certificate has critical name constraints. A client that follows them rejects a leaf with a name outside them. Clients differ, so test yours ([measured 2026-11-01](/learn/chain-private-pki/#why-one-intermediate-per-environment)).
- **Depth.** The path length is 0: the intermediate issues leaves and no further CA.
- **Use.** When the intermediate's certificate states what its certificates are for (extended key usage), issue a leaf only for those uses. The [reading note on CloudNativePG](/research/postgresql-under-cloudnativepg-and-a-private-pki-2026-11-13/) concludes that an intermediate limited to server use cannot sign client leaves that verify. That is a reading of code and documents, not a test.

## What you choose

1. **Key type: P-256 or P-384.** Both verify under a P-384 intermediate. P-256 is the one curve that every TLS 1.3 stack must support: "A TLS-compliant application MUST support digital signatures with ... ecdsa_secp256r1_sha256" (RFC 8446, section 9.1) [2]. P-384 has the larger margin, about 192 bits against about 128 [3]. NIST SP 800-52 Rev. 2, section 3.1, says "either curve P-256 or curve P-384 should be used" [4]. Do not use P-521: ETSI asks that a CA key be "at least as strong as the corresponding parameters of the certified keys" (TS 119 312, 9.5; a rule for EU trust service providers), and P-521 is stronger than a P-384 intermediate [5].
2. **Ed25519 is not recommended.** Go, the JDK and OpenSSL accept an Ed25519 leaf. But the public web rules do not allow it [7], the BSI and ETSI lists do not name it [5][6], and a PostgreSQL bug report shows `psql` failing with an Ed25519 server certificate (BUG #19050, September 2025; no fix found) [8]. AWS Private CA is expected not to sign a request with an Ed25519 key; this was not tested.
3. **Lifetime: hours to days, at most 90 days.** The tools below set their own defaults. The public web is moving to short leaves too: 200 days from 2026-03-15, 100 days from 2027-03-15 and 47 days from 2029-03-15 [9]. Its rules say they do not cover an enterprise's own PKI [9]. A leaf that lives for days is gone before anyone could revoke it ([Private PKI](/learn/chain-private-pki/#revocation)). The project's CRLs list intermediates only ([the CRL page](/reference/crl/)), so a leaf ends by its end date unless you run a list of your own.
4. **A new key at each issue.** cert-manager does this by default since v1.18.0 (`rotationPolicy: Always`) [10].
5. **A subject alternative name (SAN) always.** Under a DNS name constraint, Go 1.27 accepted a leaf that had only a common name, and OpenSSL 3.5 rejected it ([measured 2026-11-01](/learn/chain-private-pki/#why-one-intermediate-per-environment)). Put every name in the SAN.
6. **Server and client use apart.** Give a leaf `serverAuth` or `clientAuth`, not both. Public CAs are moving this way: Chrome's root program asks that TLS certificates issued from 2027-03-15 state only `serverAuth` [11].

| Tool, version or date read | Default leaf lifetime | Default leaf key |
|---|---|---|
| step-ca, docs of 2026-02-03 | 24 hours | ECDSA P-256 |
| SPIRE 1.16.0 | 1 hour | P-256 |
| cert-manager 1.21.3 (2026-10-23) | 90 days, at least 1 hour; renewed at two thirds | RSA 2048; ECDSA 256 if only the algorithm is named |
| Vault PKI, docs of 2026-11-13 | "30 to 90 days" advised | RSA |

Source of the table: [10].

## Not tested

Nothing here was run against a ritueel intermediate. The name constraint that allows one permitted DNS zone comes with milestone M2 ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 30). A database is a case of its own: [PostgreSQL with CloudNativePG](/guides/postgresql-with-cloudnativepg/).

## Sources

1. AWS Private CA user guide, "What is AWS Private CA?" and "Manage the private CA lifecycle", https://docs.aws.amazon.com/privateca/latest/userguide/PcaWelcome.html and .../ca-lifecycle.html, read 2026-11-13.
2. RFC 8446 (August 2018), https://www.rfc-editor.org/rfc/rfc8446.txt.
3. NIST SP 800-57 Part 1 Rev. 5 (May 2020), table 2, https://doi.org/10.6028/NIST.SP.800-57pt1r5.
4. NIST SP 800-52 Rev. 2 (August 2019), https://doi.org/10.6028/NIST.SP.800-52r2.
5. ETSI TS 119 312 V1.5.1 (2024-12), tables and 9.5; it binds EU trust service providers. https://www.etsi.org/deliver/etsi_ts/119300_119399/119312/01.05.01_60/ts_119312v010501p.pdf. Its table 3 lists NIST P-256, P-384 and P-521 and no EdDSA.
6. BSI TR-02102-2, version 2026-01 (2026-01-27), tables 11 and 12: P-256, P-384, P-521 and Brainpool; EdDSA not listed. https://www.bsi.bund.de (TR-02102 pages).
7. Mozilla Root Store Policy v3.1 (effective 2026-07-01), 5.1: "Otherwise, EdDSA keys MUST NOT be included." https://raw.githubusercontent.com/mozilla/pkipolicy/master/rootstore/policy.md.
8. PostgreSQL BUG #19050, https://www.postgresql.org/message-id/19050-b7fc71875d64588a@postgresql.org, read through a search summary; the fix was not confirmed.
9. CA/Browser Forum, Baseline Requirements for TLS Server Certificates v2.3.1 (2026-10-04), sections 1.1 and 6.3.2 (ballot SC-081), https://raw.githubusercontent.com/cabforum/servercert/main/docs/BR.md.
10. cert-manager v1.21.3, `types_certificate.go`; Smallstep step-ca production considerations (updated 2026-02-03), https://smallstep.com/docs/step-ca/certificate-authority-server-production/; SPIRE v1.16.0, `doc/spire_server.md`, https://github.com/spiffe/spire; HashiCorp Vault PKI considerations, https://developer.hashicorp.com/vault/docs/secrets/pki/considerations.
11. Chrome Root Program Policy v1.8 (2026-02-05), 1.3.2, https://raw.githubusercontent.com/GoogleChrome/chromerootprogram/main/content/crp/policy.md.
