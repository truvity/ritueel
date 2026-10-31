# Contributing

Thank you for helping. This file is the entry point for work on ritueel.
The working rules are written once, in [docs/contributing/](docs/contributing.md), and published on [ritueel.id/contributing](https://ritueel.id/contributing/). People and AI agents follow the same pages.
Who decides what is in [GOVERNANCE.md](GOVERNANCE.md). Security reports go through [SECURITY.md](SECURITY.md), not through issues.

ritueel has no release yet. The first version is planned in the [roadmap](docs/roadmap.md), and its work items are the open [issues](https://github.com/truvity/ritueel/issues).

## Before you start

- Look for an existing issue or pull request first.
- For a bug, open an issue with the *Bug* form.
- For a feature, open an issue with the *Feature request* form. Wait for the maintainer's answer before you build anything large.
- For a question about direction, scope or design, open an issue with the *Decision proposal* form. See below.

## Proposing a feature

Describe the problem before the solution. Say who has the problem and what they do today.
The maintainer replies with one of: accepted, needs a decision, out of scope. New scope needs an ADR first (see [GOVERNANCE.md](GOVERNANCE.md)).

## Proposing a decision

1. Open an issue with the *Decision proposal* form.
2. When the direction is clear, open a pull request that adds an ADR from [the template](docs/decisions/0000-template.md). The steps are in [Decision records](docs/contributing/decisions.md), the format in [docs/decisions/README.md](docs/decisions/README.md).
3. The maintainer accepts the decision by merging the ADR.

## How we work

Read the page for what you are about to do:

| Before you | Read |
|---|---|
| create a branch, commit, push, open a pull request or answer a review | [Branches and pull requests](docs/contributing/workflow.md) |
| run a build, a test or a check | [Tools, checks and verification](docs/contributing/tools.md) |
| write or rewrite a decision record | [Decision records](docs/contributing/decisions.md) |
| run a spike or write up research | [Spikes and research](docs/contributing/research.md) |
| create or edit a page of the site | [Pages](docs/contributing/pages.md) and [Writing style](docs/contributing/writing.md) |
| write a name, an address, an id or anything secret | [Public content and secrets](docs/contributing/public-content.md) |
| contribute with an AI agent | [AI agents](docs/contributing/agents.md) and [AGENTS.md](AGENTS.md) |

## Keys and test devices

Never send a real key, PIN or passphrase, and never test with a device or a key someone uses for real work. Use test keys and test devices; see [Hardware tokens and cloud keys](docs/contributing/tools.md#hardware-tokens-and-cloud-keys).

## Licence

ritueel is MIT licensed. By sending a contribution you agree that it is licensed under the [LICENSE](LICENSE).
