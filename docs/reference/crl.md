---
title: Root-signed CRLs, version 1
description: The CRL each ritueel root signs to revoke an intermediate certificate, its profile, cadence and the rules for a relying party, with test vectors.
sidebar:
  order: 8
---

*Not built yet. This is the page that [ADR 0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/#revoking-an-intermediate-a-crl-for-each-root) leaves for the format, cadence and rules; the code is [issue #30](https://github.com/truvity/ritueel/issues/30), in M2, and its [test vectors](/reference/crl/#test-vectors) match this page.*

An intermediate certificate is revoked by a certificate revocation list (CRL), the standard way an X.509 client learns that a certificate it can still build a chain to must not be used (RFC 5280, section 5). Each root signs a CRL of its own, because a CRL is per issuer, and a client that builds a path through either root may ask for either list ([Two roots in practice](/learn/two-roots/#what-to-expect-from-clients)). A root that has revoked nothing signs an empty one, so that the client always has a current list to check.

ritueel puts **no CRL distribution point in any certificate** it issues ([the profile](/reference/hand-off-contract/#what-is-issued): "Anything else: absent"). A relying party configures the file, the way a server is told which CRL file to load. The operator's pipeline publishes the files; the names a relying party fetches them under are the operator's choice.

## Files

| File | Content |
|---|---|
| `crl-<label>.pem` | The CRL of the root `<label>`: one `X509 CRL` in PEM armour (RFC 7468), with LF line endings and Base64 in lines of 64 characters. |

ritueel writes the CRL of every active root into `products/<sequence>/` with the other trust products ([the directory](/reference/directory/#the-layout)). A ceremony **signs** the CRL of the root that signs it, and **copies unchanged** the newest CRL of every other active root, so the folder of any sequence holds a current CRL for each root and the same directory gives the same bytes.

## When a root signs its CRL

- **At every ceremony in which the root signs,** whether or not anything changed. It is one more planned signature in the ceremony, counted in the plan's touches, with the kind `crl` ([the plan](/reference/ceremony-record/#the-plan)). It drops entries for certificates that have expired by then.
- **When a root is made** (`init`, `root add`), with no entry, so that every active root has a CRL from its first day.
- **When an intermediate is revoked** (`intermediate revoke`, and `replace --revoke`): the CRL of **each root that issued a certificate of that intermediate which has not yet expired** gets an entry, so the ceremony needs the card of each of those roots. The plan names them before anything is touched. Normally one certificate of an intermediate is alive, and two for about a month while two yearly ceremonies overlap, so one card is the usual case and two the exception. A cloud root is one root.
- **When the card that issued a live certificate is lost,** its CRL cannot be signed again, and the answer is the one for a lost root: the root leaves the root list and the CA bundle, and with it everything it issued ([a lost root card](/guides/lost-root-card/)).

A revoked root stops publishing its CRL. A relying party that still trusts it has not taken the new root list.

## The profile

Version 2 (RFC 5280, section 5.1). A relying party can check every row.

| Field | Value |
|---|---|
| Signature | `ecdsa-with-SHA384`, by the root's X.509 key (the key of the root certificate, which has `cRLSign`). |
| Issuer | The subject of the root's certificate. |
| `thisUpdate` | The ceremony time, as `UTCTime` (RFC 5280 uses `GeneralizedTime` only from 2050). |
| `nextUpdate` | 25 calendar months after `thisUpdate`: the same day and time of the month, or the last day of the month if it has none. |
| Authority key identifier | Not critical. The `keyIdentifier` of the root, computed as in its certificate ([RFC 7093](https://datatracker.ietf.org/doc/html/rfc7093), method 1). |
| CRL number | Not critical. The trust sequence of the ceremony that signed it. It grows with every signing of this CRL and is not consecutive: a root that did not sign at a sequence keeps the number of its last CRL. |
| Revoked entries | One for each unexpired certificate of a revoked intermediate: its serial number, the ceremony time as the revocation date, and a reason code (non-critical). |
| Reason codes | `keyCompromise`, `superseded` or `cessationOfOperation`, from `intermediate revoke --reason compromise`, `superseded` or `cessation`. A reason of `unspecified` is not written, as RFC 5280 asks. |
| Anything else | Absent: no issuing distribution point, no delta CRL, no freshest CRL. A critical extension a reader does not know makes the CRL unusable (RFC 5280, section 5.2), so ritueel writes none. |

**Why 25 months.** The cards alternate by year, so a root signs about every second year, and its CRL has to stay current until the next time it signs: two yearly ceremonies and a month for a late one. A CRL that lasted 13 months would be expired for most of every other year, and a client that checks CRLs refuses an expired one. The cost is that a CRL says less about how recently its issuer was used; the root list's 13 months still do that for the whole system, and a missed ceremony shows there first.

**What a CRL does not say.** An entry lasts until the certificate it names expires, which is at most 13 months. After that the entry is useless, and the next signing of that CRL drops it. A CRL says nothing about OpenPGP: a subkey is revoked by a revocation signature and a keyring package without it ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#revocation)).

## How a relying party reads it

A relying party holds, for each root it trusts, the last good CRL of that root. It checks a new CRL in this order; the first check that fails gives the reason code, and the party keeps the CRL it holds.

| # | Check | Code |
|---|---|---|
| 1 | The file is one PEM `X509 CRL` that parses, is version 2, is signed with `ecdsa-with-SHA384`, has a CRL number, and has no critical extension. | `malformed` |
| 2 | Its issuer is the subject of the certificate of an active root of the root list the party holds, in the CA bundle it holds. | `unknown-signer` |
| 3 | The signature verifies with that root's key. | `signature-invalid` |
| 4 | The CRL number is not lower than the held CRL's of the same issuer. | `rollback` |
| 5 | When the numbers are equal, the file is byte for byte the held one. | `sequence-conflict` |
| 6 | The party's clock is not before `thisUpdate`. | `not-yet-valid` |
| 7 | The party's clock is before `nextUpdate`. | `expired` |

A CRL whose number equals the held one and whose bytes are the same passes: ritueel copies an unchanged CRL into every later sequence. When the CRL a party holds passes `nextUpdate` and no newer one has arrived, it keeps the CRL and raises a warning, as for the root list; a TLS library that treats an expired CRL as a failure will fail, which is the reason for the cadence above. These codes belong to the party and are not sent anywhere.

**Is this certificate revoked.** A certificate is revoked when the current CRL of its issuing root lists its serial number. The party takes the issuer from the certificate, so it needs the CRL of each root that may have issued a certificate in the chains it accepts, and both when two roots are active. With OpenSSL this is `openssl verify -CAfile ca-bundle.pem -crl_check -CRLfile crl-A.pem -CRLfile crl-B.pem CERT`: it reports a listed certificate as `certificate revoked` and refuses an expired CRL with `CRL has expired` (OpenSSL 3.5.5, checked 2026-11-01 with the vectors' files). Servers built on OpenSSL take the same file in their own setting (for example nginx `ssl_crl` and PostgreSQL `ssl_crl_file`, from their documentation).

**The command.** `ritueel crl verify FILE --bundle FILE [--held FILE] [--cert FILE]` runs these checks on `FILE`, against the CA bundle that lists the roots the party trusts (its first line names the sequence of the root list; a root not in it is not trusted) and the CRL the party holds. `--cert FILE` also says whether the certificate is listed: exit code 3 with the code `revoked`. It signs and writes nothing ([Commands](/reference/cli/#commands-for-the-trust-products-after-m1)).

## Test vectors

The vectors are in [`testdata/crl/v1/`](https://github.com/truvity/ritueel/tree/main/testdata/crl/v1). They are public material only, made by the same run of [`generate.py`](https://github.com/truvity/ritueel/blob/main/testdata/hand-off/generate.py) as the hand-off vectors, so the roots are the same test roots: A and B are active and Z is on no list. Root A signed at trust sequence 7 and root B at sequence 6, and B's CRL is still current at the clock of the vectors.

- `manifest.json` names each root with its pin, two intermediate certificates (one issued by A, one by B) with their serial numbers, every CRL with its signer, number, times and revoked serials, every case and every revocation case.
- A case gives the CRL the party holds (`held`, or `null`), the CRL it receives (`candidate`), the labels of the active roots (`roots`), the clock if it is not the manifest's `2026-11-15T12:00:00Z`, and the expected outcome: `accept`, `refuse` with a reason code, or `warn` with a warning.
- A revocation case names a certificate and a CRL and expects `revoked` or `good`.

| Group | Cases |
|---|---|
| Accepted | A first CRL of each root; the CRL of the root that did not sign for a year, still current; an update that lists a certificate; the same CRL again. |
| Refused | A lower number (`rollback`); another CRL with the same number (`sequence-conflict`); a CRL by Z, and one by a root that left the root list (`unknown-signer`); a CRL changed after signing (`signature-invalid`); an expired one (`expired`); one that is not yet valid (`not-yet-valid`); one with a critical extension, and one signed with SHA-256 (`malformed`). |
| Warned | The held CRL expired and no newer one came. |
| Revocation | A certificate that a CRL lists is `revoked`; the same certificate against an earlier, empty CRL, and the other root's certificate against its own CRL, are `good`. |

CI checks that the manifest names every file of the set, that the pins match the root files, that every CRL parses and has the number, times and serials the manifest says, that its signature verifies except the one a case expects to fail, and that each revocation case agrees with its CRL (`just check-vectors`). The files were also run through `openssl verify -crl_check` on 2026-11-01 (OpenSSL 3.5.5): the listed certificate is reported revoked, the others are accepted, and the expired CRL is refused.

## Choices made

| Choice | Chosen | Other options | Why |
|---|---|---|---|
| How an intermediate is revoked for X.509 | A CRL that each root signs, which a relying party loads. | OCSP; a distribution point in every certificate; no revocation, only short lives; a revoked-certificate list in the root list. | A CRL is a file, which fits a tool that runs a ceremony once a year and publishes nothing live. OCSP needs a responder that signs online, which ritueel never holds. A distribution point would name a host in a certificate that outlives it, and TLS libraries do not fetch it by default anyway. Short lives are already the case (13 months) and cannot answer a theft this month. The root list pins keys, and an entry per certificate would make it grow with every renewal. |
| Which root signs | The issuer of each certificate, each for its own list. | One root of the year signs one CRL for both roots (an indirect CRL); a single CRL for all. | Standard clients accept a CRL only from the issuer, or from a CRL issuer the certificate names, which ritueel's certificates do not. An indirect CRL is poorly supported. |
| Validity of a CRL | 25 months. | 13 months, like the root list; both roots sign at every ceremony. | The cards alternate. 13 months would leave every other CRL expired, and signing both at every ceremony needs both cards every year, which is what the alternation exists to avoid. |
| CRL number | The trust sequence. | A counter of its own for each CRL. | One counter ([ADR 0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/#one-counter-the-trust-sequence)). RFC 5280 asks only that the number grows, so gaps are allowed. |
| Reason codes | Three, from the command. | All of RFC 5280's; none. | Nothing reads the others. A reason is what a person reading the CRL gets for free. |
| Format | PEM. | DER. | The files OpenSSL-based servers load are PEM, and the other trust products are text. A DER file is a conversion away for a party that wants it. |

## Follow-ups

- The code: writing, signing and reading the CRLs, `intermediate revoke` with its entries, and a test that the same inputs give the same bytes ([issue #30](https://github.com/truvity/ritueel/issues/30)).
- The plan's signature kind `crl`, and the finding kind `crl` of `status` ([issue #30](https://github.com/truvity/ritueel/issues/30)).

## Standards

| Standard | Used for |
|---|---|
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) | The CRL profile, section 5, and the root's key usage `cRLSign`. |
| [RFC 7093](https://datatracker.ietf.org/doc/html/rfc7093) | The key identifier. |
| [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468) | PEM armour. |
