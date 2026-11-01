---
title: An OpenPGP authentication subkey for SSH
description: Log in to SSH servers with an OpenPGP authentication subkey that lives on a card, using gpg-agent as the SSH agent or the card through PKCS#11.
sidebar:
  order: 10
---

*These steps use `gpg` and `ssh`, which exist today. Making the subkey with ritueel, so that an offline master key binds a subkey born on the card, is planned ([issue #18](https://github.com/truvity/ritueel/issues/18)). Try everything on a test key first. To learn how the master key and the subkeys fit, read [the OpenPGP custody chain](/learn/chain-openpgp/).*

An OpenPGP key can log you in to SSH servers. The key is a subkey with the *authentication* flag (`A`), kept on a card, so it cannot be copied off your computer and each use needs the PIN and, if the card asks, a touch. The master key stays offline.

## What you start with

- A card with an authentication subkey born on it, bound by your master key. A signing and an encryption subkey may be on the same card.
- `gpg` 2.2 or later with `scdaemon`, and an `ssh` client.
- The card's PIN in your password manager.

## Way 1: gpg-agent as the SSH agent

This is the usual way. `gpg-agent` speaks the SSH agent protocol and uses the card through `scdaemon`.

1. **Turn on SSH support.** Add `enable-ssh-support` to `~/.gnupg/gpg-agent.conf`, then restart the agent: `gpgconf --kill gpg-agent`.
2. **Point SSH at the agent.** In your shell profile, set `SSH_AUTH_SOCK` to the output of `gpgconf --list-dirs agent-ssh-socket`.
3. **List the key SSH sees.** `ssh-add -L` should print one line for the authentication subkey. If it does not, plug the card in and run `gpg --card-status` once so `gpg` learns the key.
4. **Export the public half.** `gpg --export-ssh-key <fingerprint>!` prints the line to put in `authorized_keys`, or to hand to the CA that signs SSH certificates ([SSH](/learn/chain-ssh/)). The `!` selects that exact subkey.
5. **Log in.** `ssh host`. The agent asks for the PIN, and touches follow your card's policy.

## Way 2: the card through PKCS#11

An SSH client can also load a PKCS#11 module that talks to the card directly, with `PKCS11Provider` in `~/.ssh/config` or `ssh -I`. Which module you need depends on the card: OpenSC's module reads OpenPGP cards, and a YubiKey's PIV applet has its own module. The key then comes from whatever the module exposes, not from `gpg`.

Choose this when you do not want `gpg-agent` in the loop. Know the cost: a module and `scdaemon` both want the card, and a program that holds it keeps the others out. Do not run both at once, and keep the root cards, which are used only at ceremonies, away from your daily card.

## How you know it worked

- `ssh -v host` says it offers the key by its fingerprint and the server accepts it.
- Unplug the card and the login fails. That is the point.

## When something goes wrong

- **The agent offers no key.** Another program holds the card. Close it, or restart `scdaemon`.
- **A wrong PIN three times blocks the PIN.** Do not retry guesses. The admin PIN unblocks it; see [recover](/learn/recover/) if the card is lost instead.
- **The card is lost.** The key on it cannot be used by anyone without the PIN. Remove its public key from every `authorized_keys` and CA list, then revoke the subkey ([Revoke a key](/guides/revoke-a-key/)).

## Drill

Do all of this on a test key and a throw-away server first. End the drill by removing the key from the server and checking that the login now fails.
