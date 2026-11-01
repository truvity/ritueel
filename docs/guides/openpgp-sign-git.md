---
title: Sign git commits and tags
description: Sign git commits and tags with an OpenPGP signing subkey on a card, and how GitHub and GitLab decide whether to show a signature as verified.
sidebar:
  order: 11
---

*These steps use `git` and `gpg`, which exist today. Making the subkey with ritueel is planned ([issue #18](https://github.com/truvity/ritueel/issues/18)). Try them on a test key and a scratch repository first.*

A signed commit says that the holder of a key made it. A signed tag says that the holder of a key blessed a release point. Neither says the code is good; both say who stood behind it.

## What you start with

- A signing subkey (`S`) on a card, bound by your master key, and its public key.
- `git` and `gpg`, and the card's PIN.
- A user ID on the key with an email address you also use in git and on your hosting platform.

## Steps

1. **Tell git which key to use.** `git config --global user.signingkey <fingerprint>!`. The `!` makes `gpg` use that exact subkey and not some other signing subkey.
2. **Sign by default.** `git config --global commit.gpgsign true` and `git config --global tag.gpgsign true`. Without these, use `git commit -S` and `git tag -s`.
3. **Make a commit and a tag in the scratch repository.** `gpg-agent` asks for the PIN, and the card may ask for a touch.
4. **Check them.** `git log --show-signature -1`, `git verify-commit HEAD` and `git verify-tag <tag>`. Both commands read `gpg`'s verdict; they need the public key in your keyring.
5. **Upload the public key to your platform** (below) and push.

## How platforms decide a signature is verified

A platform cannot see your master key or your card. It checks three things:

| Platform checks | What it means for you |
|---|---|
| The signature is valid and made by a key the platform has. | Upload your public key to your account, with the subkeys. |
| The key's user ID includes the email of the committer. | The email in the key must be one you also use in git. |
| That email is verified on the account. | Verify the email on the platform first. |

GitHub and GitLab show a "Verified" badge when all three hold. If you rotate the subkey, upload the new public key; if you revoke one, upload the revocation too, so the platform stops treating it as good. Signatures made earlier may stay shown as verified or turn unverified depending on the platform and the revocation reason, so choose a soft reason (*superseded*) for retirement and a hard one (*compromised*) for theft ([Revoke](/learn/revoke/)).

Some platforms offer *vigilant mode*, which marks unsigned commits as unverified instead of leaving them unmarked. Turn it on: an attacker's commit in your name is then visible.

## SSH signing as an alternative

Newer git can sign with an SSH key (`gpg.format ssh`). Platforms show it as verified as well, once the SSH public key is registered as a signing key. It is simpler, and it ties the signature to the key and not to an OpenPGP identity. Prefer OpenPGP when you also sign releases with the same identity; prefer SSH signing when git is all you sign.

## How you know it worked

- `git verify-commit` says a good signature from the expected fingerprint.
- The platform shows the commit as verified.
- Unplug the card and try to commit: it fails.

## When something goes wrong

- **"Unverified" with a good local signature.** The email in the key does not match the commit's, or the email is not verified on the account.
- **Signing fails in an editor or in CI.** `gpg` has no terminal for the PIN prompt. Set `GPG_TTY=$(tty)`, or use a pinentry program that has a window.
- **The card asks for a touch you did not expect.** A background process is signing. Find it before you touch.
