---
title: 'After the ceremony: who uses what ritueel makes (2026-11-11)'
description: Who consumes the public key, the root list, the CA bundle and the SSH CA key list, how far ritueel can help, and what was not checked.
sidebar:
  order: 8
---

## Question

After a ceremony, who reads what ritueel has made (the public OpenPGP key, the revocation, the root list, the CA bundle, the SSH CA key list, the intermediates), what does each consumer need from the holder, and how much of that can ritueel do for the holder without holding a secret or a right it should not hold? This feeds [record 0011](../decisions/0011-publishing-and-what-to-do-after-a-ceremony.md).

## When

2026-11-11, by reading the services' own pages and sources. Nothing was installed, uploaded, signed in to or run; the pages were read on that day and can change.

## Verdict

**Publishing to keyservers is the one thing worth automating fully.** Only keyservers take public data from anyone, without an account. Everything else needs the holder's rights (a login at a code host, administrator rights on a machine, a role in a cluster), so ritueel prints what to do, writes a file, or reads a public address back and compares it with the bundle. cert-manager in the company's clusters gets its certificates from the system that issues every day (sluis), so nothing is built for it. Decided in [record 0011](../decisions/0011-publishing-and-what-to-do-after-a-ceremony.md).

## Method

Read the pages and sources named in the table below. Each claim is labelled:

- **READ**: the page was opened and the sentence is on it. A fetch tool summarises a page, so a quotation is close to verbatim and is checked against the page before it goes into a record.
- **SOURCE**: the source code of the service or its documentation source was read, and not run.
- **UNVERIFIED**: seen in a search result, taken from a second-hand page, or reasoned from a standard. No UNVERIFIED claim is a fact of a record.

Earlier results are not repeated: the facts about keyservers, the web key directory and the other channels for the release keys are in [release key publication channels](./release-key-publication-channels-2026-11-01.md), and what the verifiers do with a revocation is in [the verifier matrix](./openpgp-verifier-matrix-2026-11.md).

## What the setup over- and under-counts

- No upload was made and no command was run. Every claim about how a server or a tool behaves is the documentation's or the source's, not a measurement.
- A fetch tool summarises pages. A number, a version or a quotation that matters is opened again and compared before it is relied on.
- Versions: the pages were unversioned unless the table says so. Documentation changes without notice, so every row is as of 2026-11-11.
- The setup under-counts the work of each consumer's own rules (for example, whether a mail provider drops a verification mail). It over-counts nothing in the other direction: it did not look for reasons to automate more.

## Numbers

One row per output and consumer. The last column holds the addresses read on 2026-11-11; the sentence that carries a finding is quoted in the row.

| Output | Consumer | What ritueel does | Source address (read 2026-11-11) |
|---|---|---|---|
| Public OpenPGP key | keys.openpgp.org | Sends, after a typed confirmation, then reads back. A key may be uploaded with one POST, and a request to verify an address follows. READ. "An email address can only be associated with a single key." The server asks for the click in the mail itself, so ritueel cannot do it. A revoked primary has no user IDs there, and plain `gpg` ignores that kind of revocation (see the verifier matrix). A user ID with no address is not distributed. | https://keys.openpgp.org/about/api, https://keys.openpgp.org/about/faq |
| Public OpenPGP key | The server's own code | The server merges later uploads into the key it holds. The server is "not maintained or officially supported as deployable software", so it is a service to use, not one to copy. SOURCE for the merge logic (not run). | https://gitlab.com/keys.openpgp.org/hagrid (README, `database/src/lib.rs`) |
| Public OpenPGP key | Other keyservers (HKP) | Sends with the HKP add call, which takes one form field with the armoured key. READ. HKP cannot withdraw: "BEWARE that deletion and replacement actions do not prevent the old key data from being resubmitted or resynced from the server's peers." So the preview says a published user ID cannot be withdrawn. | https://hockeypuck.io/admin.html (Hockeypuck 2.4.1 current), https://www.ietf.org/archive/id/draft-gallagher-openpgp-hkp-10.txt (section 6.2, `/pks/add`) |
| Public OpenPGP key | `gpg` users | `gpg` ignores key signatures received from keyservers since version 2.2.17, because keys were flooded with faked signatures. So the key ritueel sends carries no third-party signatures. READ. | https://raw.githubusercontent.com/gpg/gnupg/master/NEWS (2.2.17) |
| Public OpenPGP key | Maven Central, Launchpad | Keyserver part is the publish step. Maven Central lists the keyservers it reads, and says it "can only verify against a primary key"; whether a certify-only primary with a signing subkey passes is not known (open question). Launchpad shows the key after a mail decrypt, and the holder does that. READ. | https://central.sonatype.org/publish/requirements/gpg/, https://documentation.ubuntu.com/launchpad/user/how-to/import-openpgp-key/ |
| Public OpenPGP key | Web key directory | Later; the specification is an Internet-Draft, version 22, and the directory sits on the holder's own domain. The managed variant needs a CNAME in the holder's DNS. READ. | https://www.ietf.org/archive/id/draft-koch-openpgp-webkey-service-22.txt, https://keys.openpgp.org/about/usage-wkd |
| Public key | GitHub | Prints the key file, the link where the key is added and the line `gh gpg-key add FILE`, as text. The add-key page documents no prefill and asks the holder to authenticate. The default token of the `gh` tool has no key scope ("The minimum required scopes for the token are: repo, read:org, and gist."), and deleting a key needs the `admin:gpg_key` scope. There is no update call: delete, then add. Old commits stay verified: GitHub "will not re-verify previously signed commits or retroactively adjust their verification status". READ. Prefill while logged in was not tested. | https://docs.github.com/en/rest/users/gpg-keys, https://docs.github.com/en/authentication/managing-commit-signature-verification/adding-a-gpg-key-to-your-github-account, https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification, https://cli.github.com/manual/gh_auth_login |
| Public key | GitLab | Prints the same kind of text. GitLab differs on revocation: "Past commits signed by this key are marked as unverified." A key cannot be edited ("you cannot edit it"). SOURCE (documentation source, master). | `doc/user/project/repository/signed_commits/gpg.md` in https://gitlab.com/gitlab-org/gitlab |
| Root certificates | The local trust store of one machine | Writes one certificate file per active root, and prints the add and undo commands. The Debian tool wants "one certificate per file, and not multiple certificates in a single file". The root is issued again at each ceremony, so a check later matches by the key pin, not by file name. A root whose key is in a file on the same computer gives "complete power to intercept secure requests from your machine" (mkcert), so ritueel says: do not install. The commands are never run with administrator rights by ritueel. READ. | https://manpages.debian.org/trixie/ca-certificates/update-ca-certificates.8.en.html (ca-certificates 20250419), https://github.com/FiloSottile/mkcert (README) |
| Root certificates | Chrome and Firefox on Linux | Not served by the system store, so the guide covers them separately. "On Linux, Chromium uses the NSS Shared DB." Of Firefox, "ImportEnterpriseRoots only works on Windows and macOS." READ. | https://chromium.googlesource.com/chromium/src/+/main/docs/linux/cert_management.md, https://firefox-admin-docs.mozilla.org/reference/policies/certificates/ |
| CA bundle | trust-manager | Prints a `Bundle` snippet with the roots inline. During a rotation both roots must be trusted together: "Rotation requires that both root certificates are trusted simultaneously for a period". READ (chart v0.26.0, `v1alpha1`). A PEM with a comment line was not tested with it. | https://cert-manager.io/docs/trust/trust-manager/ |
| Intermediate | cert-manager (CA issuer) | Gets its certificates from sluis in the company's clusters. The issuer needs the whole chain and a key in a cluster Secret, which ritueel cannot verify: "ensure that `tls.crt` contains the issuer's full chain in the correct order: issuer -> intermediate(s) -> root." and "There's no automatic rotation for the CA certificate in the Secret you configured." READ (quickstart uses v1.21.3). | https://cert-manager.io/docs/configuration/ca/ |
| SSH CA key list | `sshd` | Prints the `TrustedUserCAKeys` line, the reload and a placeholder `known_hosts` line. "Keys are listed one per line; empty lines and comments starting with '#' are allowed." READ. | https://man.openbsd.org/sshd_config |
| JSON Web Key Set | Token verifiers | Nothing. The set belongs to the system that signs tokens; only the chain link is shared with it. READ. | https://sluis.id/reference/keys/ |
| Intermediate | Vault, OpenBao, AWS Private CA, step-ca, Istio | Later, with a change of the hand-off contract. Vault, OpenBao and AWS Private CA send a bare request, with at most basic constraints, and the contract refuses a request without the critical extensions. Most of them keep the intermediate key in software (a Secret, storage, a file); step-ca and AWS differ (optional KMS or a card, or a key the cloud holds). READ for the pages that rendered. | See the list below the table. |
| Intermediate | SPIRE, Linkerd, kubeadm | Out. Linkerd takes P-256 only and the contract has one curve (READ). SPIRE's path-length need is ritueel's reasoning from RFC 5280, not a statement of SPIRE (UNVERIFIED). kubeadm's cluster CA is not a use. | See the list below the table. |
| Revocation of an intermediate | All the systems above | None of them was found to read the root's revocation list; cert-manager says it has no such support. So "revoke an intermediate" means replacing the file or Secret and removing the trust. READ for cert-manager, otherwise no statement found. | https://cert-manager.io/docs/configuration/ca/ |
| The local page | A page on the user's machine | A page on localhost that can trigger an action is a known weak spot. Six incidents of local servers, 2016 to 2025, had one cause: the server answered any request that reached it. Four were read: Transmission 2.92 and earlier (2018, DNS rebinding), Zoom for Mac (2019, a local web server on port 19421), Ollama before 0.1.29 (2024, DNS rebinding) and MCP Inspector before 0.14.1 (2025). The other two (Trend Micro, 2016; Vite, 2025) are UNVERIFIED, from search summaries. Cookies do not isolate by port ("Cookies do not provide isolation by port.") and an extension "can read and modify page content using the standard Web APIs". A button that triggers a send is refused for this reason. | https://www.openwall.com/lists/oss-security/2018/01/11/1, https://www.zoom.com/en/trust/security-bulletin/ZSB-19001/, https://www.nccgroup.com/research/technical-advisory-ollama-dns-rebinding-attack-cve-2024-28224/, https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g, https://www.rfc-editor.org/rfc/rfc6265 (8.5), https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Content_scripts |
| Unlock factor | Password-manager passkeys | A passkey in a password manager is a synced software credential, not one that cannot be copied. The vendor's pages say a saved passkey is "like any other item" of a vault, that it is shared through shared vaults, and that the phone apps can export it. So [record 0002](../decisions/0002-where-a-key-lives.md) offers none for now: the recovery passphrase kept in the manager already gives what a passkey would add, and a key file is opened in the offline system, which has no network, no password manager and no browser; a passphrase can be typed there, a passkey cannot. READ on the vendor's support pages; whether PRF works in each stable build is UNVERIFIED. | https://support.1password.com/save-use-passkeys/, https://1password.com/blog/how-save-manage-share-passkeys-1password |

### Pages read for the X.509 consumers

Opened on 2026-11-11; most were unversioned "latest" or a main branch.

| Consumer | Pages |
|---|---|
| Vault | https://developer.hashicorp.com/vault/api-docs/secret/pki, https://developer.hashicorp.com/vault/docs/secrets/pki |
| OpenBao | https://openbao.org/docs/secrets/pki/ (version 2.7.x; the API page did not render) |
| step-ca | https://smallstep.com/docs/tutorials/intermediate-ca-new-ca/, https://smallstep.com/docs/step-ca/certificate-authority-server-production/, https://smallstep.com/docs/step-ca/cryptographic-protection/ |
| AWS Private CA | https://docs.aws.amazon.com/privateca/latest/userguide/PcaExternalRoot.html, https://docs.aws.amazon.com/privateca/latest/userguide/PCACertInstall.html |
| SPIRE | https://github.com/spiffe/spire/blob/main/doc/plugin_server_upstreamauthority_disk.md |
| Istio | https://istio.io/latest/docs/tasks/security/cert-management/plug-in-ca-cert/ |
| Linkerd | https://linkerd.io/2/tasks/generate-certificates/ (docs 2.20) |
| kubeadm | https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/ |

## Roads not taken

These are the roads of [record 0011](../decisions/0011-publishing-and-what-to-do-after-a-ceremony.md), each with its reason in the record. In short:

- **A second program that publishes**, or **print only**: the first keeps the old rule true at the price of two tools and two configs; the second gives up publishing, which the maintainer asked for.
- **A token or an application of ritueel at a code host**: the default token has no key scope, deleting needs a wide scope, and a stored token is a secret ritueel is meant not to hold.
- **A button in the page that sends the holder to a code host, or that uploads to a keyserver**: no documented prefill, the host asks for a password or passkey, and an extension can click a button. The page shows the command instead ([record 0010](../decisions/0010-the-engine-the-process-and-the-page.md)).
- **Running the trust-store commands with administrator rights**: one step less, but a tool would change what a whole machine trusts, from a bundle that cannot vouch for itself.
- **Asking servers whether their CA bundle is current**: no such call was found.
- **A JWK or JWKS output**, **a cert-manager that holds its own intermediate**, and **automating the click in the keyserver mail or DNS records**: the reasons are in the table above.

## Open questions

Each is a question a test answers, not a choice; the recommendation is to run the test before the thing depends on it. The maintainer decides when.

- keys.openpgp.org with a certify-only primary and its subkeys, and whether a later update needs no new click in the mail. This comes from the server's source, not from a run. Recommend one upload of a throwaway key by hand before the first real publish.
- Maven Central with a certify-only primary: its page says it can only verify against a primary key. Recommend a test before the first signed release ([record 0009](../decisions/0009-release-keys-and-the-keyring.md)).
- GitHub prefill of the add-key form while logged in. No login was started.
- Whether Go exposes the full chain a service presents, which a check of a live service needs.
- Whether cert-manager re-reads a changed Secret without a restart, and whether trust-manager accepts a PEM that starts with a comment line.
- The OpenBao API page and some Istio pages did not render. Istio's root-rotation steps and whether istiod accepts P-384 are not known.
- Local trust: no command was run, and "name constraints are enforced" is from source files.

## Changes made

None. Nothing was installed, uploaded or signed in to, and no key or account was touched.

## Raw logs

Not kept in the repository. The addresses above are the evidence; the pages can be opened again.

Decided in [record 0011](../decisions/0011-publishing-and-what-to-do-after-a-ceremony.md).
