---
title: SSH host and client keys under your SSH CA
description: Which host keys, client keys and certificate lifetimes to choose under a P-384 SSH CA key, and how to rotate a host key. Advice that binds no one.
sidebar:
  order: 15
---

*Advice that binds no one: every sentence is a choice for your team. ritueel's own part is the [SSH CA key list](/reference/ssh-ca-key-list/), which takes ECDSA P-384 keys only. The CA keys that sign day-to-day certificates stay with the system that holds them ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rules 25 and 26). This page is about the keys those certificates certify. No ritueel command is used. Sources are numbered and listed at the end, read on 2026-11-13.*

## What a P-384 CA can sign

A CA of one type can certify a key of another: "it is possible for a RSA certificate key to be signed by a Ed25519 or ECDSA CA key and vice-versa" (OpenSSH `PROTOCOL.certkeys`) [1]. OpenSSH has accepted an ECDSA CA key since 5.7 (2011) [2].

One test on 2026-11-13, not yet written up as a research note: with a P-384 CA key, OpenSSH 10.2p1 `ssh-keygen -s` signed an Ed25519 user key and a P-384 host key, and Go 1.27.0 with `golang.org/x/crypto/ssh` v0.59.0 (`CertChecker`) accepted both certificates [3]. Not tested: a login to a running `sshd`. Five other clients were read in their documentation only, and it does not say which CA key types they check [3]. Test the clients you use.

## Host keys

Use an ECDSA host key (P-384 or P-256) with a host certificate from your host CA. BSI TR-02102-4 (2026-01), 3.6, lists `ecdsa-sha2-*` for server authentication and does not list Ed25519 [4]. Add an Ed25519 host key only where no host runs in FIPS mode, a mode of the operating system. Red Hat's documentation says: "the Ed25519 algorithm is not FIPS-140-compliant, and OpenSSH does not work with Ed25519 keys in FIPS mode" [5]. OpenSSH makes RSA, ECDSA and Ed25519 host keys itself if they are missing, so remove the ones you do not want [5].

## People: a key on hardware

The BSI asks that signature keys be "stored and processed in a secure manner" (TR-02102-4, 4.1) [4]. A YubiKey gives an SSH key in three ways:

- **PIV**, through PKCS#11 (`ssh -I libykcs11.so`): P-256, P-384 or RSA; Ed25519 from firmware 5.7.4 [6].
- **An OpenPGP authentication subkey**, served by `gpg-agent`: P-256, P-384, P-521, Brainpool or Ed25519 [6].
- **FIDO2**, `ecdsa-sk` (P-256) or `ed25519-sk`, since OpenSSH 8.2 [7]. `gpg-agent` does not serve it. This guide reads `ed25519-sk` as under the FIPS-mode limit above (a reading, not a test).

The project decides one thing for a person: each day card gets an authentication subkey, which serves SSH through `gpg-agent` ([record 0008](../decisions/0008-a-persons-own-key.md), rule 9; the steps: [An OpenPGP authentication subkey for SSH](/guides/openpgp-ssh-authentication/)). The other two ways are yours to choose.

## Services: short-lived user certificates

A service has no person to touch a card. Give it a user certificate that lives for hours, for a key made new each time and held in memory or in a key management service (KMS). Mozilla's guideline asks that machine keys be "unique per usage" [8]. You need an issuing service; ritueel provides none.

## Lifetimes: the tools' own defaults

- step-ca (source on master): user certificate 16 hours, at most 24; host certificate 30 days, at most 30 [9].
- Teleport 18: "from a few hours to minutes" [10]. Cloudflare Access (2019-10-25): "valid for 2 minutes" [11].
- OpenSSH: `ssh-keygen -s -V` sets the validity [12].

So hours or less for user certificates, and days to weeks for host certificates that renew themselves. Replace a host key when the machine is rebuilt and at most every one to two years (NIST SP 800-57 Part 1 Rev. 5, 5.3.6: "no more than one or two years, depending on its usage environment") [13].

## Rotating a host key

- **With a host certificate:** make a new key, have the host CA sign it, switch. A client that trusts the CA sees no failure: "You'll never see a host key verification failure again" (Smallstep) [9].
- **With a plain key:** `UpdateHostKeys` in `ssh_config` lets a server send replacement keys before the old ones are removed. It works only when "the host was authenticated using a plain key and not a certificate", and is on by default only with the default `UserKnownHostsFile` and no `VerifyHostKeyDNS`. Add the new key, wait until clients have learned it, then remove the old one [12].

## Revocation

A certificate of hours ends by itself. A whole SSH CA is withdrawn by the next signed SSH CA key list; there is no revocation signature ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 29). One key can be refused by a host with a key revocation list (`ssh-keygen -k`, `RevokedKeys` in `sshd_config`), or by an `@revoked` line in `known_hosts` [12]. See [SSH](/learn/chain-ssh/).

## Sources

1. OpenSSH `PROTOCOL.certkeys` at tag V_10_0_P1, https://raw.githubusercontent.com/openssh/openssh-portable/V_10_0_P1/PROTOCOL.certkeys (later replaced by an Internet-Draft, `draft-ietf-sshm-cert`).
2. OpenSSH 5.7 release notes, https://www.openssh.org/releasenotes.html.
3. The test of 2026-11-13 above; Go `x/crypto/ssh` v0.59.0 (`certs.go`, `keys.go`), https://github.com/golang/crypto; libssh https://api.libssh.org/master/, PuTTY https://the.earth.li/~sgtatham/putty/latest/htmldoc/Chapter4.html, Paramiko changelog, AsyncSSH https://asyncssh.readthedocs.io/en/latest/api.html, Apache MINA SSHD `docs/standards.md`.
4. BSI TR-02102-4, version 2026-01 (2026-01-27), https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-4.pdf.
5. Red Hat Enterprise Linux 9 and 10, "Using secure communications between two systems with OpenSSH", https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/securing_networks/assembly_using-secure-communications-between-two-systems-with-openssh_securing-networks.
6. Yubico YubiKey 5 technical manual, pages "Smart Card (PIV Compatible)" and "OpenPGP", https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-piv.html and `yk5-apps-openpgp.html`; `gpg-agent` as in [the SSH guide](/guides/openpgp-ssh-authentication/).
7. OpenSSH `PROTOCOL.u2f`, https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL.u2f; release notes of 8.2 (2020-02-14), source 2.
8. Mozilla "OpenSSH" guideline, https://infosec.mozilla.org/guidelines/openssh (no revision date on the page).
9. Smallstep: `certificates` source `authority/config/config.go`, https://raw.githubusercontent.com/smallstep/certificates/master/authority/config/config.go; blog "use-ssh-certificates", https://smallstep.com/blog/use-ssh-certificates/.
10. Teleport 18, "Signature Algorithms" and "Authentication", https://goteleport.com/docs/reference/deployment/signature-algorithms/ and https://goteleport.com/docs/reference/architecture/authentication/.
11. Cloudflare, "Public keys are not enough for SSH security" (2019-10-25), https://blog.cloudflare.com/public-keys-are-not-enough-for-ssh-security/.
12. OpenBSD manual pages `ssh-keygen(1)`, `sshd_config(5)`, `ssh_config(5)`, `sshd(8)`, OpenBSD-current of 2026-10-30, https://man.openbsd.org.
13. NIST SP 800-57 Part 1 Rev. 5 (May 2020), 5.3.6, https://doi.org/10.6028/NIST.SP.800-57pt1r5.
