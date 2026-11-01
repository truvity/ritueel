---
title: Private PKI
description: The custody chain of a private PKI. Your own root, per-environment intermediates limited by name constraints, workload certificates, and distributing the root.
sidebar:
  order: 9
---

A private PKI is a chain you run end to end. Nobody includes your root in a browser; you put it in every trust store that needs it. In exchange you decide everything else.

## The chain

| Link | Key | Held by | Lives in | Authority came from |
|---|---|---|---|---|
| Root | Your root key. | You, the holder. | Two cards in two places, or a cloud key with a replica. | Self-signed at the first ceremony; extended at each yearly ceremony. |
| Intermediate | One per environment: production, staging, development, perhaps one per region or team. | The system that issues for that environment. | A cloud key service or a card, close to the system. | A certificate signed by the root at a ceremony, renewed by re-signing. |
| Leaf | A workload or host certificate. | The workload or host. | Its memory or its disk. | Issued automatically by the intermediate. |

## Why one intermediate per environment

A break in one environment should not reach the others. If staging has its own intermediate, a leaked staging key can sign certificates for staging and for nothing else. That only holds if the intermediate is *limited*.

**Name constraints** are how an intermediate is limited. The intermediate's certificate says which names it may issue for, for example only `*.staging.example.com` and a range of addresses. A client that follows the constraint rejects a certificate for any other name, even if the signature is valid.

**Clients differ, so test them.** Measured on 2026-11-01 with a throwaway root whose intermediate permitted DNS `example.test` and the addresses `10.0.0.0/8`:

| Client | A name outside the constraint | A leaf with only a common name, no SAN | A common name `evil.com` plus an in-scope SAN | An email SAN, with no email constraint |
|---|---|---|---|---|
| Go 1.27 `crypto/x509` | Rejected | **Accepted** | Accepted | Accepted |
| OpenSSL 3.5 `verify` | Rejected | Rejected | Accepted | Accepted |

What follows:

- **Constrain DNS and IP, and always issue with SANs.** A name type you do not constrain is open, and a client that reads only the common name can be led past a constraint.
- **A constrained root is still a root.** If its key leaks, the constraint is only as good as each client's enforcement.
- **The constraint is set at the ceremony.** ritueel's policy can require name constraints on every X.509 intermediate it signs ([the policy](/reference/directory/#ritueelyaml)), and refuse a request that is wider than the allowed hosts. Today the policy can list URI hosts only; permitted and excluded DNS subtrees, and excluded IP ranges, are planned, because an intermediate that issues for DNS names and one environment that must not reach another need them.

Other limits worth setting: a path length of zero below the intermediate, and extended key usage so that a server-authentication intermediate cannot sign client certificates.

## Distributing your root

The hard part of a private PKI is not making the root, it is getting it everywhere it is needed and getting it out again.

| Where it must be | How it usually gets there |
|---|---|
| Debian and Ubuntu | A PEM file named `.crt` in `/usr/local/share/ca-certificates`, then `update-ca-certificates`. |
| Systems with p11-kit | `trust anchor /path/to/root.crt`. |
| Firefox | The enterprise policy `Certificates.Install`, or `ImportEnterpriseRoots` to read the system store. |
| Android | Apps that target API 24 or later ignore user-added roots unless their network security config opts in. |
| iOS | Install a profile, then enable full trust for the root; device management trusts it automatically. |
| Windows | `certutil -addstore Root file`, or group policy. |
| Application stores (Java, Python, Node, Go with a custom pool) and container images | A file the application is told to use, or a layer baked into the base image and rebuilt when the root changes. |
| Systems that update their own trust | A signed root list that they verify. |

Commands and policies are from the vendors' documentation, read on 2026-11-01; check them for your versions.

ritueel builds what outsiders install: a *CA bundle* of the current roots, and a signed *root list* for systems that update themselves. Because a root change takes as long as the slowest client, [moving from one root to another](/learn/transitions/) needs an overlap, and every client you forgot is a client that breaks.

## Revocation

Short-lived leaf certificates make most revocation unnecessary: a leaf that lives for days is gone before anyone could revoke it. For an intermediate, the root signs a CRL that lists it. See [revoke](/learn/revoke/).

## Where ritueel fits

ritueel is for the first row of the table: the root, the ceremonies that give each intermediate its certificate, and the bundle and lists that carry the root to the clients. The system that holds an intermediate and issues the leaves is a different product, which meets ritueel through the [hand-off contract](/reference/hand-off-contract/).
