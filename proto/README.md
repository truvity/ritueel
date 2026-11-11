# The API of the local page

Status: a design, version `v1alpha1`. Nothing serves it yet: the program is not built, and the page's demo answers the same calls from fixtures (`ui/src/fixtures/`) through an in-memory transport. It may change in any pre-release.

The API between ritueel's local page (`ui/`) and the ritueel process, written in Protobuf (package `ritueel.local.v1alpha1`). The program will serve it with ConnectRPC; the page calls it with `@connectrpc/connect`. See [the local page](https://ritueel.id/tools/local-page/).

**No call takes or returns a secret, a PIN or a passphrase.** There is no field for one, and none will be added. The page is a view: it never confirms a ceremony. `ritueel run PLAN --confirm DIGEST` happens in the terminal, on the ceremony machine. The only value that goes from the page to the process, other than choices from a fixed list, is the digest of a plan, which is public.

## What is here

| Path | What |
|---|---|
| `ritueel/local/v1alpha1/common.proto` | Shared words: `Severity`, `Store`, `Intention`, `Subject`, `LedgerStatus`. |
| `ritueel/local/v1alpha1/inspect_service.proto` | `InspectService`: six read calls. |
| `ritueel/local/v1alpha1/plan_service.proto` | `PlanService`: the wizard, three calls. |
| `../buf.yaml`, `../buf.gen.yaml` | The buf module (lint `STANDARD`) and the TypeScript generator, at the repository root. |
| `../ui/src/gen/` | The generated TypeScript, committed so the page builds without buf. |

## Generate and check

`just proto-lint` lints (buf, from devbox). `just proto-gen` lints and regenerates `ui/src/gen/` with `protoc-gen-es` from the page's lock file (`ui/node_modules`). `just proto-check` regenerates and fails on any difference, so the committed code is always what the generator makes. Both run in CI.

The Go side comes with the program: `protoc-gen-go` and `protoc-gen-connect-go` as two more entries in `buf.gen.yaml`, and `option go_package` in the three files.

## The services

| Service | Call | Request | Response | Writes? |
|---|---|---|---|---|
| `InspectService` | `GetSummary` | `GetSummaryRequest` | `GetSummaryResponse` (folder, as_of, ledger, due items, finding counts, counts, pending plans, setup steps) | no |
| | `ListFindings` | `ListFindingsRequest` (min severity) | `ListFindingsResponse` (`Finding`: reason, severity, subject, evidence, fix command, fix intention, learn path) | no |
| | `ListRoots` | `ListRootsRequest` | `ListRootsResponse` (`Root`: keys by side and card, `OpenPgpCertificate` with primary, user IDs, `SubkeySet` by year and card, `Subkey`; `CloudKey`; `DelegatedKey`) | no |
| | `ListCeremonies` | `ListCeremoniesRequest` | `ListCeremoniesResponse` (`LedgerStatus` and `Ceremony`, newest first) | no |
| | `ListCards` | `ListCardsRequest` | `ListCardsResponse` (`Card`: `PivApplication` in six `PivRow`s of four `Slot`s, `OpenPgpApplication`, `Fido2Application`) | no |
| | `ListTrustFiles` | `ListTrustFilesRequest` | `ListTrustFilesResponse` (`TrustFile` with its check) | no |
| `PlanService` | `ListIntentions` | `ListIntentionsRequest` | `ListIntentionsResponse` (`IntentionOption`: applicable or greyed with a reason, recommended) | no |
| | `StartPlan` | `StartPlanRequest` (intention, due ids, finding ids, target, `Answer`s) | `StartPlanResponse` (`Question`s, or the `Plan`, or a refusal) | no (builds in memory) |
| | `SavePlan` | `SavePlanRequest` (plan id, digest) | `SavePlanResponse` (path, digest, `written`, notice, run command, what to copy and bring, file preview) | **yes**, one inert file; the demo writes nothing |

Enums, all with an `_UNSPECIFIED = 0` first value and the enum name as prefix:
`Severity`, `Store`, `SubjectKind`, `Intention`, `ChainState` (common);
`DueKind`, `RootKind`, `RootState`, `RootKeyKind`, `DelegatedKeyKind`,
`DelegatedKeyState`, `SubkeyUsage`, `SubkeyState`, `RevocationReason`,
`SubkeyOrigin`, `CeremonyKind`, `CeremonyOutcome`, `CardKind`, `CardState`,
`ApplicationUse`, `SlotState`, `SlotUse`, `PinRule`, `TouchRule`,
`TrustFileKind`, `TrustCheckResult` (inspect); `QuestionKind`, `Requirement`,
`FolderChangeAction` (plan).

## Which calls feed which screen

| Screen | Calls |
|---|---|
| **Start** (getting started, what is due) | `GetSummary` (due items, finding counts, ledger banner, setup steps, pending plans). `ListIntentions` for the "Make a plan" button. |
| **Findings** | `ListFindings`. Each finding's `fix_intention` opens the wizard through `StartPlan`; its `fix_command` and `learn_path` are shown as given. |
| **Key view** (a certificate by year and by card; a root and its delegated keys) | `ListRoots`. Card names come from `ListCards` (join on serial); findings about a key come from `ListFindings` (join on `subject.identifier`). |
| **History** (the ledger) | `ListCeremonies` (the banner is its `ledger`). |
| **Cards** (inventory and the use of every slot) | `ListCards`. |
| **Trust files** | `ListTrustFiles`. |
| **Wizard: goals** | `ListIntentions`. |
| **Wizard: questions and preview** | `StartPlan` twice: first without answers (questions), then with them (the plan: steps, folder changes, digest, equivalent command, run command). |
| **Wizard: save and hand-over** | `SavePlan` (path, digest, what to copy and bring, what the plan file holds). In the demo `written` is false and `notice` says so. |

## Things a designer must know

1. **Text is data.** Every string in a response is written by the folder, not
   by the program: user IDs, card names, summaries. Render it as text only, cap
   its length, and show any non-ASCII, bidirectional, zero-width or control
   character as a `U+XXXX` escape. The fixture is plain ASCII; real data will not be.
2. **A key is its full fingerprint.** `fingerprint` and `Subject.identifier` are
   complete (40 hexadecimal characters for OpenPGP, 64 for an X.509 or SSH key).
   Never identify a key by a name or a short id. Names (`label`, `name`) can repeat.
3. **Unset means something.** An unset `expires_at` on a key means *no expiry*
   (that is the finding). An empty `card_serial` on a `SubkeySet` means the set
   is not on a card. An unset `Intention` on a finding means *no wizard goal*;
   show the command only.
4. **Cards not in the inventory.** `SubkeySet.card_in_inventory` is false for
   `00000101` and `00000102`; there is no `Card` for them. Design that state.
5. **The row layout is fixed.** `PivApplication.rows` always has six rows of
   four slots in the order 9a, 9c, 9d, 9e, then 82 to 95. Row 1 is the card's own
   jobs; `Root.card_row` is 1 to 6 as drawn, so roots start at row 2. A slot's
   `SlotState` is empty, used, reserved (planned, not born) or spare (a row no root
   owns yet); on a day-to-day card all PIV slots are empty, not spare.
6. **Counting days.** Use `as_of` from `GetSummary` as "now". `DueItem.severity`
   is already computed (notice at 60 days, alert at 30, critical at 14).
7. **The command is shown, never run.** `fix_command`, `equivalent_command`
   and `run_command` are exact strings to display and copy. Their names follow
   `docs/reference/cli.md` where a command exists there; a few (`personal
   primary extend`, `personal primary add`, `personal userid revoke`, `personal subkey revoke`, and the `--key` flag that names a
   cloud key to adopt) are proposals until the command set is built; `card adopt`
   and `card check` are the names cli.md gives, marked Proposed there, so the page
   must show them as given and not parse them.
8. **The wizard has three outcomes.** `StartPlan` returns questions, a plan, or
   a refusal. Questions are choices only; there is no free-text answer, so no
   place a secret could be typed. `ListIntentions` marks goals that do not apply,
   with the reason; show them greyed.
9. **Nothing happens here.** A plan's steps are what `ritueel run` does on the
   ceremony machine. A `Requirement` says that a card, a PIN, a touch or a
   passkey unlock is needed there; the PIN is never in the page. `SavePlan`
   in the demo answers `written: false` with a notice and a file preview: show
   the preview as "what saving would write".
10. **`int64` is a string in JSON** (`size_bytes`), and `Timestamp` is an
    RFC 3339 string; the generated types turn them into `bigint` and `Timestamp`.
11. **One addition to the world of the brief:** a ninth finding, "a cloud key is
    waiting to be adopted" (`alias/example-staging-signing`), so that the wizard
    goal "adopt a key" has something to adopt, since the personal key and the
    cloud root are already adopted.
