---
title: After a ceremony
description: 'What ritueel prints after a ceremony and what to do with it: keyservers, a code host, a trust-manager Bundle, sshd and a machine trust store.'
sidebar:
  order: 8
---

*Design phase: not built yet. ritueel prints this list after every ceremony; the command words are decided, and the flag, form and list names marked proposed are not ([record 0011](../decisions/0011-publishing-and-what-to-do-after-a-ceremony.md)). The commands of other tools below are for you to run by hand; ritueel runs none of them and holds no token. Use example names; the snippets are not tested.*

The rule is short: ritueel changes only your bundle. The one thing it may send out is your public OpenPGP key, to the keyservers you list. For everything else it prints what to do. This page is that "what to do", one section for each place a ceremony's result goes.

## What ritueel prints

After every ceremony ritueel prints a list of next steps. Each line says what changed, who needs it and how. For an OpenPGP key the list ends with an optional last step, publishing it. Its name, NEXT STEPS, is proposed.

## Your public OpenPGP key to the keyservers

This is the one step ritueel does itself, and it is a separate command run after a ceremony, never inside one: the offline system has no network. The command word is `ritueel publish`; its flags, and the details of the steps below (the preview, the read-back, the refusals and the stricter confirmation for a revocation), are proposed. It runs as a separate process that never opens a card and never reads a token, and it is left out of the offline build.

1. **List your keyservers** in `ritueel.yaml`, one of the wanted files you write (a `keyservers` block, proposed). There is no default that sends; the examples in the file are commented out.
2. **Read the preview.** It shows every user ID (a user ID without an address is marked: keys.openpgp.org drops it, the older kind of server keeps it), the subkeys, the fingerprint, the bundle and each server address. It says that what is published cannot be withdrawn.
3. **Type the confirmation:** the first eight characters of the primary's fingerprint and the name of the server (proposed). Result: the key is sent, read back from the server and compared with what was sent. If the server already holds the same key, ritueel says there is nothing to send.

What ritueel cannot do:

- **keys.openpgp.org** shows an address only after the owner of the address clicks a link in a mail. ritueel cannot click it. The state of each server and address is one of not sent, sent and unconfirmed, confirmed, or failed (proposed).
- **A key cannot be withdrawn** from the older kind of server (HKP). A user ID you published stays.
- **Two primaries with one release address** collide on keys.openpgp.org, which keeps one key for each address. ritueel warns, sends the newer primary there and both to the other servers (proposed).
- **A revocation** goes to a second kind of server too, because a revoked primary has no user IDs on keys.openpgp.org and plain `gpg` ignores that kind of revocation: `ritueel publish --revocation FILE` (proposed), after a stricter confirmation (sixteen characters), and never from a scheduler. See [Revoke a key](/guides/revoke-a-key/).
- **Refused:** a test root, and any run while a ceremony is running.

Not tested: whether keys.openpgp.org accepts a certify-only primary with its subkeys, and whether a later update needs no new click in the mail. The first real upload is one throwaway key, by hand ([issue #18](https://github.com/truvity/ritueel/issues/18)).

## A code host

For GitHub and GitLab (Codeberg is not checked, see below) ritueel prints text and does nothing else: the path of the public key file, the link where the key is added, and the command of the host's own tool. It holds no token and does not call the tool.

For GitHub:

- the file: the path of the armoured public key that ritueel prints;
- the link: [github.com/settings/gpg/new](https://github.com/settings/gpg/new);
- the command: `gh gpg-key add FILE`;
- undo: `gh gpg-key delete KEY-ID`. Deleting needs the wide `admin:gpg_key` scope, which the default token of `gh` lacks. Not run; the scope hint of this command was not checked.

For GitLab: avatar, Edit profile, Access, GPG keys, Add new key, paste the contents of the file. A key cannot be edited there: delete it and add it again.

Codeberg: not checked. The web steps were not read. The host's API documents a signed token when no email of the key is verified on the account; read the host's page before relying on it.

The host has no update call. To replace a key, delete the old key and add the new one again; between the two, new commits show as unverified. When a key is revoked, GitLab marks the past commits signed by it as unverified; GitHub does not re-verify old commits ([sign git commits](/guides/openpgp-sign-git/#how-platforms-decide-a-signature-is-verified)). Read on 2026-11-11 in the hosts' documentation; no login was made.

## A trust-manager Bundle with the roots inline

If a cluster runs trust-manager, a `Bundle` can carry your roots inline. The CA bundle is public, so the file is safe to commit. Use the root-only CA bundle, `ca-bundle.pem`, from the newest trust set of the bundle, never a chain.

```yaml
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: acme-roots
spec:
  sources:
    - inLine: |
        -----BEGIN CERTIFICATE-----
        (placeholder: the PEM text of every certificate in the CA bundle)
        -----END CERTIFICATE-----
  target:
    configMap:
      key: ca.crt
```

Undo: delete the Bundle (`kubectl delete bundle acme-roots`) once the new root keys are in somewhere else; not run. During an overlap both root keys stay in. Add the new root key first; remove the old one only after the leaf certificates have moved to the new chain ([Rotate a key](/guides/rotate-a-key/)). Not tested: trust-manager with the comment line at the top of ritueel's file.

## sshd

The SSH CA key list has a file made for sshd, `ssh-user-ca-keys.pub` ([the format](/reference/ssh-ca-key-list/#the-file-for-sshd)). Copy it to the server and tell sshd:

```text
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/ssh-user-ca-keys.pub
```

Reload sshd (send it `SIGHUP`, or use the service manager's reload). Undo: remove the `TrustedUserCAKeys` line and the file, then reload; not run. Host certificates need a line in each client's `known_hosts`. ritueel does not know your host names, so it prints the line with a placeholder:

```text
@cert-authority *.example.com ecdsa-sha2-nistp384 AAAA...placeholder-for-the-host-CA-key
```

## Certificates for clusters come from the issuing system

cert-manager in the company's clusters gets its certificates from the system that issues every day (sluis). It holds no intermediate of its own, so there is nothing to build ([record 0011](../decisions/0011-publishing-and-what-to-do-after-a-ceremony.md)).

Some other consumers send bare requests, without the limits the hand-off contract demands, or keep the intermediate key in software. Under the contract as it stands, ritueel refuses their requests ([record 0011](../decisions/0011-publishing-and-what-to-do-after-a-ceremony.md), rule 10). A change of the contract is on the roadmap, after the first version.

## The trust store of one machine

This section is proposed, not decided. For one computer ritueel writes one certificate file per active root key and prints the add and undo commands for that system. It never runs them, and never runs with administrator rights. It refuses a test root, a retired root key, an expired root list and a root list with a lower sequence than this machine has seen (proposed). The commands below are examples with example names; the Debian and Ubuntu commands follow the [manual page of `update-ca-certificates`](https://manpages.debian.org/trixie/ca-certificates/update-ca-certificates.8.en.html), and the macOS commands were read on 2026-11-11 from a mirror of the `security(1)` man page (keith.github.io/xcode-man-pages/security.1.html) and not run. The macOS undo removes the trust setting and may leave the certificate in the keychain; it was not run.

**Debian and Ubuntu.** One certificate in each file.

```text
sudo cp acme-root-A.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

Undo:

```text
sudo rm /usr/local/share/ca-certificates/acme-root-A.crt
sudo update-ca-certificates --fresh
```

**macOS.**

```text
sudo security add-trusted-cert -d -r trustRoot -p ssl -k /Library/Keychains/System.keychain acme-root-A.crt
```

Undo:

```text
sudo security remove-trusted-cert -d acme-root-A.crt
```

Read these warnings first:

- **The root becomes trusted for every site,** with no name limits.
- **Compare the key pin** that ritueel prints with a value kept outside the bundle. The bundle cannot vouch for itself.
- **Never install a root whose key is a software file on this computer.** Whoever reads the file can intercept secure requests from the machine.
- **Never install a test root or a retired root key.**
- **Chrome and Firefox on Linux do not read the system store.** They need separate steps (read from the makers' pages on 2026-11-11, not run).
- **No store reads the root key's revocation list.** To stop trusting a revoked root key, remove its file with the undo command above.

## Is the world up to date?

The question means reading a public copy and comparing it with the bundle. There are three reads (proposed):

1. **The keyserver read-back** after `ritueel publish`.
2. **The chain a live service presents:** `ritueel check tls HOST:PORT` says which intermediate and root the service shows. Whether Go exposes the whole presented chain is not researched.
3. **A root list fetched from a web address,** piped into a verify command. Hosts check themselves this way, with the signed, numbered root list; ritueel asks no server about its bundle.

Every result prints the time, the source and the facts, and claims no more than this: "On TIME, source X served a copy with these facts. This is not proof that the key is not revoked or that other copies are the same." It never says "safe".

## Not covered

For a web site, a JSON Web Key Set and the key file of your own software, ritueel gives only the content and the links: the public key, and where to take it from. A JSON Web Key Set belongs to the system that signs tokens; ritueel makes none.
