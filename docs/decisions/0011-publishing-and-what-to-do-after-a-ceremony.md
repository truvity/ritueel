# 0011 — ritueel changes only your bundle, sends out only a public OpenPGP key, and prints what to do after a ceremony

**Status:** Accepted
**Date:** 2026-11-13

## Decision

1. ritueel changes only your bundle. The one thing it may send out is your public OpenPGP key, to the keyservers you list. For everything else it prints what to do.
2. Publishing is a separate command, run after a ceremony and never inside one, because the offline system has no network.
3. The publish command runs as a separate process that never opens a card, and it is left out of the offline build.
4. ritueel keeps a managed list of the keyservers to publish to, and sends to no other.
5. The keyserver step is shown in the page with its command, and the terminal sends after a typed confirmation. The page has no button, because a published user ID cannot be withdrawn and a browser extension could click it.
6. After a ceremony ritueel prints what to do. For an OpenPGP key the optional last step is publishing it.

7. For a web site, a JSON Web Key Set and the public key file of the user's software, ritueel gives only the content and the links; the owner of the site or the software does the rest.
8. For a code host, ritueel holds no token and does not call the host's own tool.
9. cert-manager in the company's clusters gets its certificates from the system that issues every day; it holds no intermediate of its own. Nothing is built for it.
10. Consumers that send bare requests, without the limits the hand-off contract demands, or keep the intermediate key in software are not served: under the contract as it stands ritueel refuses their requests.

## Why

Only keyservers take a public key from anyone without an account, so publishing there is the one send ritueel can do without anyone's rights. Everything else needs the holder's rights, and ritueel holds none: no token, no administrator rights. Publishing is no part of a ceremony: the offline system has no network. A published user ID cannot be withdrawn, so each send is typed in the terminal and the page only shows it. The sources are in the research note [after the ceremony](../research/after-the-ceremony-consumers-2026-11-11.md).

## What it costs

- A publish process with network code, and a build without it, must be built and tested.
- A person types a confirmation for every send.
- What is published and copied by servers cannot be withdrawn.
- ritueel does not do the host's, the machine's or the site's part: the holder or their pipeline follows the printed list.

## Roads not taken

- **A second program that publishes.** ritueel itself would publish nothing, but there would be two tools and two configs.
- **Print only, publish nothing.** Nothing to build, but it gives up automated publishing to the keyservers.
- **Publishing as a step inside the ceremony.** One flow, but the offline system, where copyable keys are used, has no network.
- **A button in the page that publishes.** A published user ID cannot be withdrawn and a browser extension could click it; the page shows the step with its command instead.
- **ritueel updates a web site or the key file of your software.** ritueel has no rights there; the owner of the site or the software does it.
- **A JSON Web Key Set output.** A key set belongs to the system that signs tokens; only the chain link is shared with it.
- **cert-manager holds its own intermediate.** It needs a contract change, its key would sit unattested in a cluster Secret that ritueel cannot verify, and it has no automatic rotation and no revocation list.

## Not yet proven or only proposed

- **Proposed.** What the send step shows: a preview of every user ID (those without an address are marked: keys.openpgp.org drops them), the subkeys, the fingerprint and each server, with the line that what is published cannot be withdrawn; a typed confirmation of the first 8 characters of the primary's fingerprint and the server's name ([#18](https://github.com/truvity/ritueel/issues/18)).
- **Proposed.** What the send step does and refuses: the key rebuilt from the verified record in the bundle with third-party signatures stripped; after the send a read-back that compares what the server serves with the bundle; a refusal of a test root and while a ceremony runs; no token read; "nothing to send" when the server holds the same key ([#18](https://github.com/truvity/ritueel/issues/18)).
- **Proposed.** No consent or state file kept by ritueel: the keyserver is the state, and a file could disagree with it ([#18](https://github.com/truvity/ritueel/issues/18)).
- **Proposed.** No unattended uploads from a scheduler: no one has to be there, but an upload cannot be withdrawn, so each one needs a person's typed confirmation ([#18](https://github.com/truvity/ritueel/issues/18)).
- **Proposed.** The list is a short keyservers block in ritueel.yaml, a wanted file (a person writes only wanted files: [record 0006](0006-bundle-history-and-trust-files.md), rule 5); `new` ships no default that sends; keys.openpgp.org and keyserver.ubuntu.com are commented examples; no built-in default list of keyservers, because a first run could send a key somewhere nobody chose ([#18](https://github.com/truvity/ritueel/issues/18)).
- **Proposed.** A revocation also goes to a second kind of server (HKP), because one kind alone does not reach every user; a hard revocation is published beside the keyring file ([record 0009](0009-release-keys-and-the-keyring.md), rule 18) and only a soft one stays inside it ([record 0009](0009-release-keys-and-the-keyring.md), rule 19); the signature is not stored in the bundle or printed; the file is the one the holder keeps apart; its typed confirmation is stricter, 16 characters ([#18](https://github.com/truvity/ritueel/issues/18)).
- **Proposed.** Two kinds of server (the keys.openpgp.org interface and HKP); the state of each server and address is not-sent, sent-unconfirmed, confirmed or failed; two roots of a company with one release address: keys.openpgp.org keeps one key per address, so ritueel warns, sends the newer root there and both to the other servers ([#18](https://github.com/truvity/ritueel/issues/18)).
- **Proposed.** The printed list of next steps says for each step what changed, who needs it and how; its name (NEXT STEPS) is proposed ([#18](https://github.com/truvity/ritueel/issues/18)).
- **Proposed.** Code hosts: the file, the add-key link and the host tool's command line (for GitHub `gh gpg-key add FILE`); the host has no update call (delete, then add) ([#18](https://github.com/truvity/ritueel/issues/18)).
- **Proposed.** Calling the host's tool is later and, with reading back an account's public keys, needs the maintainer's word (a green result would mean the account lists the key, not that it is your account) ([#18](https://github.com/truvity/ritueel/issues/18)).
- **Proposed.** ritueel holds no token and no application of its own at a code host (the default token has no key scope, deleting a key needs a wide scope, and a stored token is a secret ritueel is meant not to hold), and no button in the page sends the person to the code host to confirm (no prefill is documented, a password or passkey is asked there, and the click cannot be saved) ([#18](https://github.com/truvity/ritueel/issues/18)).
- **Proposed.** The local trust store of one machine: one certificate file per active root and the add and undo commands for that system (Debian and Ubuntu, macOS first), never run and never with administrator rights (one confirmation less, but a tool would change what the whole machine trusts, over a bundle that cannot vouch for itself) ([#203](https://github.com/truvity/ritueel/issues/203)).
- **Proposed.** The local trust store, refusals and warnings: refused for a test root, a retired root, an expired root list and a lower sequence than the machine has seen; the key pin is printed to compare with a value kept outside the bundle; a warning that the root is trusted for every site; a root whose key is in a software file on the same computer: do not install; `check --local` by key pin later ([#203](https://github.com/truvity/ritueel/issues/203)).
- **Proposed.** "Is the world up to date?" means reading a public copy and comparing it with the bundle: the keyserver read-back, the chain a live service presents, and which intermediate and root it shows (whether Go exposes the full presented chain is not researched), and a root list fetched from a web address; ritueel never claims more than "this source served this copy at this time" and never says "safe": every result prints the time, the source and the facts and says it is not proof ([#203](https://github.com/truvity/ritueel/issues/203)).
- **Proposed.** ritueel does not ask servers about their bundles, hosts check themselves with the signed numbered root list (no such call was found, and a server can only answer with what it chooses to say) ([#203](https://github.com/truvity/ritueel/issues/203)).
- **Proposed.** The guide "After a ceremony" (unpublished) with three snippets: a trust-manager Bundle with the roots inline, the sshd lines for the SSH CA key list, and that cluster certificates come from the issuing system ([#30](https://github.com/truvity/ritueel/issues/30)).
- **Proposed.** Whether keys.openpgp.org accepts a certify-only primary with its subkeys, and whether later updates need no new click in the mail, is not known; one upload of a throwaway key by hand answers it before the first real upload; ritueel does not automate the click in the keyserver mail: the click is the server's rule and ritueel has no rights there ([#18](https://github.com/truvity/ritueel/issues/18)).
- **Proposed.** The command words `publish` and `check` are two of the thirteen of the command reference. These names are proposed, not decided: the flag in `publish --revocation FILE`, the keyservers block, the list called NEXT STEPS and the form `ritueel check tls HOST:PORT` ([#18](https://github.com/truvity/ritueel/issues/18)).
- **Proposed.** Build order: M2 no code (this record, the guide, the page security additions, a fix of answers/ against requests/STEM); M3 the list of next steps after apply, publish, the user ID change and the latest-plan option; M4 the check of a live service and the trust-store text ([#30](https://github.com/truvity/ritueel/issues/30)).
- **Proposed.** Not built and not planned: outputs for SPIRE, Linkerd and kubeadm, a feed for the Debian and Arch keyrings, DNS changes; ritueel does not automate DNS records: DNS is the owner's and ritueel has no rights there ([#30](https://github.com/truvity/ritueel/issues/30)).
