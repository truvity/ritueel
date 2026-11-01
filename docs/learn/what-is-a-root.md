---
title: What is a root?
description: A root is the key that other keys and people trust without further proof. What it is in X.509 and in OpenPGP, and what is at stake if it is lost or stolen.
sidebar:
  order: 1
---

Trust has to start somewhere. When your browser accepts the certificate of a website, it has not met the website. It follows a chain of signatures to a certificate that was already on your computer before you opened the browser. That certificate, and the key behind it, is a **root**.

## Two places a root shows up

| | X.509 (certificates, TLS, code signing) | OpenPGP (signatures on software, mail, git) |
|---|---|---|
| The root is | A *root CA certificate* and its private key. | The *primary key*, also called the master key, of an identity. |
| Outsiders trust it because | It is installed in their trust store: the operating system's, the browser's, or a file your company ships. | They hold its public key in a keyring, and they have checked the fingerprint some other way. |
| What it signs | Certificates of intermediate CAs. | Certifications of identities and the bindings of subkeys. |
| Looks like | A file of a few hundred bytes of public data. | A fingerprint of 40 hexadecimal characters. |

In both worlds the root is a **public** thing and a **private** thing. The public part is given to everyone, because everyone needs it to verify. The private part is what this site is about.

## Why a root is special

Three facts make a root unlike any other key.

1. **Nobody above it vouches for it.** An intermediate that is stolen can be revoked by the root. A root that is stolen can be revoked by nobody except itself, or by a new root that outsiders are persuaded to install. Persuading them takes weeks, or years.
2. **It is trusted for everything below it.** Whoever holds the private key of a root can sign an intermediate, or a binding, that every client of that root will accept. The key does not know who is asking.
3. **It is used rarely.** A root signs a few certificates or bindings a year. That rarity is what lets you keep it somewhere safer, and less convenient, than any other key.

## What goes wrong

- **Lost.** The root key is gone, and nobody can sign under it again. Existing certificates keep working until they expire, and then everything has to move to a new root, which every client must learn to trust.
- **Stolen.** Someone else can sign things your clients accept, until the root is revoked and the revocation reaches the clients.
- **Used by mistake.** A person signs the wrong request, with a wrong lifetime or a wrong name. The signature is real, and cannot be taken back.
- **Expired unnoticed.** A root with a fixed end date runs out on a bad day.

Most of what the rest of Learn explains is a way to avoid one of these four. Next: [root and intermediate](/learn/root-and-intermediate/).
