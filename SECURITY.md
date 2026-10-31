# Security Policy

## Reporting a vulnerability

Report a vulnerability privately through
[GitHub Security Advisories](https://github.com/truvity/ritueel/security/advisories/new).

Do not open a public issue, a pull request or a discussion for a vulnerability.

Please include:

- the version or commit you tested;
- what you did, what you expected and what happened;
- a minimal way to reproduce it;
- what an attacker gains.

Do not include real keys, PINs, passphrases or personal data. Use test values and test devices.

## What to expect

The maintainer is one person. Replies are best effort, and we aim to answer within a week.
We confirm the report, agree on severity, fix it and then publish an advisory. We credit you if you wish.
Please give us reasonable time to fix a problem before you tell anyone else.

## How we fix in private

The fix is prepared out of public view:

1. We open a temporary private fork from the advisory.
2. The fix, its tests and the advisory text are written there.
3. When the fix is ready, we merge it and publish the advisory and the release together. A CVE is requested through the advisory when it applies.

If you want to propose a fix, say so in the advisory. The maintainer can invite you to the private fork.

## Supported versions

ritueel has no release yet. Until the first release, `main` is the only line, and it carries no support promise. Reports are welcome and handled the same private way. When there are releases, this table will say which are supported, in the same pull request.

## Scope

In scope: the code, workflows and published artifacts of this repository. A flaw that makes ritueel create, sign, vouch for or revoke a key it should not, or leak key material, is in scope.
Out of scope: your own key stores, your own pipeline that publishes keyring packages, third-party services, and findings that need an already-compromised workstation or key store.
