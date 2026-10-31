# Governance

This file says who decides what in ritueel, how a decision is made and kept, and how releases are numbered.
It describes the project as it is today: one maintainer, no release yet, and a plan to tighten the rules before production use.

## Branches and versions

- `main` is the only long-lived branch. Every change reaches it through a pull request.
- Versions follow semantic versioning. Until the first stable release they are pre-releases named `v0.x.y`; a `v0` minor release may break compatibility, and says so in the CHANGELOG.
- **A published version is never reused, moved or deleted.** Module proxies cache every version they have seen, so reuse breaks checksums. A tag ruleset enforces it for `v*` tags. A mistake is fixed by the next version.
- Published history is not rewritten.
- Compatibility follows semantic versioning once there is a stable release. A breaking change ships in a major release, or in a minor release that says so in the CHANGELOG, announces it and carries an upgrade note. Stored data, such as ceremony records, stays readable by the next release. The hand-off contract with other systems is versioned and checked for breaking changes.

## Roles

**Maintainer.** The maintainer is the sole maintainer today. The maintainer decides scope, accepts ADRs, grants compatibility exceptions, merges and cuts releases.

**Reviewers.** Anyone may review a pull request. A review from a non-maintainer is welcome and is read, but it does not replace the maintainer's decision. Reviewers who work in a part of the code for a long time may be named as code owners when the rules tighten (see below).

**Review agent.** An AI agent that reviews pull requests adversarially. It reads the diff, looks for faults and missing tests, and reports findings on the pull request. It is read-only: it does not edit the branch, approve alone, merge or decide scope. It is a different agent from the one that wrote the change.

**Contributors.** Anyone who sends an issue or a pull request. See [CONTRIBUTING.md](CONTRIBUTING.md). A contributor may be a person or an AI agent working for a person. The person is responsible for the work.

## Scope

ritueel owns root keys and root transitions: X.509 CA roots and OpenPGP primary keys, across key stores. It creates them, vouches for the next one, overlaps, supersedes, revokes and expires them, and it runs the ceremonies for intermediates, produces the trust artifacts, and keeps ceremony records. It does not sign online, issue leaf certificates or store secrets. The scope is recorded in [ADR 0001](docs/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates.md).
New scope enters only through an ADR that names its owner, its boundary and its non-goals.
A change to the design model (the shape of the parts and how they depend on each other) also needs an ADR.

## How a decision is made

1. **Proposal.** Open an issue with the *Decision proposal* form. State the question, the context, the options with pros and cons, and the options you would not take. Label `status:needs-decision` is added.
2. **Discussion.** Comments on the issue. The maintainer may also discuss it internally. Internal discussion can hold material that must not be public, such as details of a private deployment.
3. **ADR pull request.** When the direction is clear, someone opens a pull request that adds `docs/decisions/NNNN-title.md` with status `Proposed`. It follows the [template](docs/decisions/0000-template.md) and must list the roads not taken. The order of work is in [Decision records](docs/contributing/decisions.md); the format and the status values are in the [decisions README](docs/decisions/README.md).
4. **Accepted.** A record is `Accepted` only when every part of it is decided. The maintainer merges it with status `Accepted`, and that merge is the decision. A record with a part still open is merged as `Proposed`, with the open part tracked in an issue the record links, and a later pull request sets it to `Accepted` once the part is decided. A rejected proposal is merged with status `Rejected`, so the reasoning is kept.
5. **Changing a decision.** Records are append-only: a new ADR supersedes the old one, and the old status line says so (`Superseded by NNNN`, or `Accepted; amended by NNNN`).

Small changes that follow existing ADRs need no proposal. A pull request is enough.

### From internal reasoning to a public ADR

Draft ADRs, research and stakeholder input are written in internal discussion first. They may name deployments, accounts, teams and people.
Only the final ADR is public. When the maintainer decides:

- the final ADR is written fresh for the public repository, not copied;
- it keeps the question, the options, the decision, the consequences and the roads not taken;
- it names no private deployment, account, hostname, ticket or person other than the maintainer, and uses neutral examples (`example.com`, `acme`);
- the internal draft is marked as decided and links to the public ADR.

Roadmap, features, architecture and decisions are public. Internal reasoning and per-deployment rollout notes are not.

## Review rules

**Now.** Every change to `main` goes through a pull request. The maintainer reviews it, and the review agent reviews it too. The maintainer merges when checks pass, and findings from the review agent are answered or fixed. Changes that touch key handling, signing, revocation, trust artifacts or the hand-off contract also carry a short security note in the pull request: what could go wrong, and which test shows it does not.

**Agents.** An agent working for the maintainer may merge its own pull request when checks are green and review is done. It never decides scope, never merges another author's pull request, and never changes governance files without the maintainer.

**Later.** The rules tighten before ritueel is used for production roots. The bar is:

- a `CODEOWNERS` file;
- two approvals on a pull request;
- a named security owner for security-sensitive paths;
- an independent security review of the ceremony and key handling code.

When a rule on this list takes effect, an ADR records the date and this file is updated in the same pull request.

## Standards

Every standard ritueel claims is listed with the version it follows. A deliberate deviation from a standard needs an ADR.

## Public repository hygiene

This repository is public. Code, docs, the CHANGELOG, tests, commit messages and pull requests name no real organisation account, hostname, cluster, ticket or secret path, and no person other than the maintainer. Use neutral examples. No key material is committed.

## Changing these rules

Open a pull request that changes this file. The maintainer decides. A change that makes the rules looser needs an ADR.
