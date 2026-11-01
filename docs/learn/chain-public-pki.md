---
title: Public PKI
description: The custody chain of the public web PKI, from a CA root through intermediates to your TLS certificate, and what you do not control in it.
sidebar:
  order: 8
---

When you buy or request a certificate for a website, you are the end of a chain that somebody else runs. This page is about that chain, because knowing which parts you do not control is how you decide what to protect.

## The chain

| Link | Key | Held by | Lives in | Authority came from |
|---|---|---|---|---|
| Root | A public CA's root key. | The CA. | Audited hardware, offline. | The root programs of browsers and operating systems, which decided to include it. |
| Intermediate | A key of the CA that issues for customers. | The CA. | Hardware, online at the CA. | A certificate signed by the root at a CA ceremony. |
| Leaf | The key of your TLS certificate. | You, or your hosting provider. | Your server, your load balancer, or a managed service. | A certificate issued after the CA checked that you control the name. |

You hold only the last key. Everything above it is trusted because your visitors' devices already hold the root.

## What you do not control

- **The CA/Browser Forum rules.** The Baseline Requirements set how a CA must validate a name, how it must protect its keys, and how long a TLS certificate may live. The maximum lifetime is falling in steps, from 398 days to 200 days in March 2026, and lower after that (checked 2026-11-01; read the current ballot before you plan a renewal schedule). Plan for automatic renewal, not for a calendar reminder.
- **Certificate Transparency.** Browsers expect every certificate to be logged in public, append-only logs. A certificate you request will appear there, with its names. Do not put a secret in a hostname.
- **The root programs.** Browser and operating system vendors can remove a root, or distrust a CA after a failure. Your certificate stops working for those clients on the day they decide, whatever you did.
- **The CA itself.** If it is compromised or mis-issues, you learn from the news.

## What you do control

- **Your private key,** and where it lives. A key in a cloud key service or on a hardware token cannot be copied off the server; this is the custody question of the previous pages, at the leaf.
- **Which names you let anyone issue for.** A CAA record in DNS tells CAs which of them may issue for your domain.
- **How fast you can replace a certificate.** A certificate that you can reissue in minutes makes revocation and short lifetimes cheap.
- **Watching the logs** for certificates issued for your names that you did not ask for.

## Where ritueel fits

ritueel does not hold a public CA's keys and does not issue public certificates. This page is here because most readers start by trusting a public chain, and the same four questions about custody apply to the private chains they build next: [private PKI](/learn/chain-private-pki/).
