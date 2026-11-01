---
title: Release key publication channels (2026-11-01)
description: Where users can find and verify ritueel release keys beyond the first version, what each channel costs to keep current, and the commands for the guide.
sidebar:
  order: 3
---

## Question

Beyond the first version, which channels should publish the release keys and the keyring package, who would consume each, and which commands does the release-key guide teach for verifying? This feeds the guide ([issue #25](https://github.com/truvity/ritueel/issues/25)) and does not change [ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/), whose first version is decided: the keyring package in the user's own repository, and the primaries' fingerprints on the project's site and in its security file ([issue #28](https://github.com/truvity/ritueel/issues/28)).

## When

2026-11-01, by reading the services' own pages and the standards, not by running them. Nothing below was installed or published; the pages were read on that day and can change.

## Verdict

**Keep the first version's channels and add none now.** Each further channel serves a consumer that does not exist yet, and each is one more place to keep current at every yearly ceremony, because the keyring changes every year. If a consumer asks, the order is: GitHub releases (no new trust, it carries the files already published), then the WKD direct method (static files, a standard consumers already speak), then the keyserver; DNS `OPENPGPKEY` last, because it needs DNSSEC and serves mail clients, not package managers. What users verify with does not change: the keyring and `gpgv`, `sqv` or `gpg --status-fd`. Provenance tools are an optional second check.

## Method

Read: the keys.openpgp.org about and FAQ pages; the Internet-Draft for the Web Key Directory; RFC 7929; the GitHub CLI manual for `gh attestation verify`. The consumer of each channel was taken from what those documents say it is for. Cost was judged against ritueel's yearly cadence: every ceremony writes a new keyring, so a channel that holds a copy needs an update step after each one.

## What the setup over- and under-counts

- Nothing was run. A claim about how a tool behaves is the documentation's, not a measurement, and is marked so.
- `cosign` and `slsa-verifier` were not read; they appear only as names of tools to try, not as recommendations.
- The verifiers' behaviour on revocations and on the keyring is measured, in [the verifier matrix](/research/openpgp-verifier-matrix-2026-11/), and is not repeated here.

## Numbers

| Channel | Consumer | Kept current by | Cost and limits | Verdict |
|---|---|---|---|---|
| The user's own repository (first version) | apt and rpm users | The user's pipeline, which signs the keyring package with the current subkey | None beyond the pipeline | Decided. |
| The project site and security file (first version) | A person comparing fingerprints | A page edit after each ceremony | Trust in the site's TLS and hosting | Decided. |
| GitHub releases | Anyone who downloads the package or the plain files by hand | The release workflow, with the package | Same trust as the repository; `gh attestation verify` needs `--owner` or `--repo` and, for a reusable workflow, `--signer-workflow` (GitHub CLI manual) | Add first, if asked. |
| WKD, direct method | `gpg` and mail clients that look keys up by address | Static files under `/.well-known/openpgpkey/hu/<hash>` on the project's domain, replaced after each ceremony | The specification is an Internet-Draft (`draft-koch-openpgp-webkey-service-22`, 2026-07-22), not an RFC; the hash is the SHA-1 of the lower-cased local part in Z-Base-32 | Add second, if asked. |
| keys.openpgp.org | People who search by address | The release address owner verifies by mail; the keys are uploaded again after each ceremony | Distributes a user ID only after the address is verified; searches by address only; does not publish third-party certifications by default (its FAQ). A release address that is a role mailbox must be reachable | Not now. The ceremony would depend on a mailbox and an upload. |
| DNS `OPENPGPKEY` (RFC 7929) | Mail transfer agents | A record per address in a DNSSEC-signed zone | Experimental RFC; a lookup that is not DNSSEC-secure must fail; needs a signed zone | Not now. Mail, not packages. |

## Verification commands for the guide

The guide teaches these; each is checked against the matrix before it goes in.

| Task | Command | Note |
|---|---|---|
| Verify a detached signature with the keyring | `sqv --keyring <name>-keyring.gpg FILE.sig FILE` | Rejects a revoked key. Preferred. |
| The same with `gpgv` | `gpgv --keyring ./<name>-keyring.gpg FILE.sig FILE` | Ignores revocations: only the new keyring protects. |
| Verify with `gpg` and read the status | `gpg --no-default-keyring --keyring ./<name>-keyring.gpg --status-fd 1 --verify FILE.sig FILE` | Reject `REVKEYSIG`; the exit status is 0 for a revoked key. |
| Compare the primaries' fingerprints | `gpg --show-keys --with-fingerprint <name>-keyring.asc`, against the site and the security file | The only step that needs a second channel. |
| Optional second check, provenance | `gh attestation verify FILE --repo OWNER/REPO` | Says how the file was built, not who vouches for it. |

## Roads not taken

- **Running each service to measure it.** Would turn documentation claims into measurements, but ritueel has no key to publish and no consumer asking, so the measurement would be of nothing it ships.
- **Recommending a provenance tool.** The names are known, but none was read or run here, and provenance is a complement ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#sigstore-and-old-releases)).

## Open questions

None. Whether a consumer exists for one of the channels is for the maintainer to say when it does; the order above is the recommendation.

## Changes made

None. No machine, account or device was touched.

## Raw logs

None kept; the pages read are named under Method.
