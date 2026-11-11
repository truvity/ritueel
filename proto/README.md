# The API of the local page

Status: a design, version `v1alpha1`. The program that serves it is not built, and the page's demo answers the same calls from fixtures (`ui/src/fixtures/`) through an in-memory transport. The contract may change in any pre-release, and no breaking-change check runs.

The API between ritueel's local page (`ui/`) and the ritueel process, written in Protobuf (package `ritueel.local.v1alpha1`). The program will serve it with ConnectRPC; the page calls it with `@connectrpc/connect`. See [the demo](https://ritueel.id/demo/) and [the design of the process and the page](https://ritueel.id/design/#the-process-and-the-page).

The process is one ritueel process, the same program as the command line. The first command that needs it starts it in the background, and it is not a service: it is never installed, never started at login or boot, and never outlives logout or reboot. A bundle is the directory with a fixed structure that holds everything ritueel knows about one trust domain; in this contract no call names a bundle, and which bundle the process serves is not decided by the records (record 0010, rules 8 and 9). The process serves the command line and the page on one fixed loopback port (localhost, 127.0.0.1 only; the number is 7488, record 0010). There are two kinds of token. A full-rights token, read from a file only the user can read, is for the command line. A page-rights token is for the browser, is used once, becomes an `HttpOnly`, `SameSite=Strict` cookie and can call only the reads and `SavePlan`: no call that confirms, signs, creates a key or runs a ceremony is open to it, and the digest is typed in the terminal. Every request is checked for its `Host` and, separately, its `Origin`. Before the command line sends a confirmation or a PIN, the listener proves that it knows the secret in the token file. There is one exclusive lock per bundle. The process keeps no ceremony state and no PIN, and it ends after 15 minutes without a call (never in the middle of a running ceremony), at once on a stop command, and at logout or reboot. Other programs of the same user can reach the port while the process runs, so the page is trusted no more than any other web request. The rules are in [record 0010](../docs/decisions/0010-the-engine-the-process-and-the-page.md), rules 6 to 12.

**No call takes or returns a secret, a PIN or a passphrase.** There is no field for one, and none will be added. The page is a view: it never confirms a ceremony. `ritueel --dir BUNDLE run PLAN --confirm DIGEST` happens in the terminal, in the offline system or on your workstation. The only value that goes from the page to the process, other than choices from a fixed list, is the digest of a plan, which is public.

## What is here

| Path | What |
|---|---|
| `ritueel/local/v1alpha1/common.proto` | Shared words: `Severity`, `Store`, `Intention`, `Subject`, `HistoryStatus`. |
| `ritueel/local/v1alpha1/inspect_service.proto` | `InspectService`: six read calls. |
| `ritueel/local/v1alpha1/plan_service.proto` | `PlanService`: the wizard, three calls. |
| `../buf.yaml`, `../buf.gen.yaml` | The buf module (lint `STANDARD`) and the TypeScript generator, at the repository root. |
| `../ui/src/gen/` | The generated TypeScript, committed so the page builds without buf. |

## Generate and check

`just proto-lint` lints (buf, from devbox). `just proto-gen` lints and regenerates `ui/src/gen/` with `protoc-gen-es` from the page's lock file (`ui/node_modules`). `just proto-check` regenerates and fails on any difference, so the committed code is always what the generator makes. It also fails on any hand edit of `ui/src/gen/`. Both run in CI.

The Go side comes with the program: `protoc-gen-go` and `protoc-gen-connect-go` as two more entries in `buf.gen.yaml`, and `option go_package` in the three files. The generated handlers are mounted on the one listener; the page-rights token reaches only the reads and `SavePlan`.

## The services

| Service | Call | Request | Response | Writes? |
|---|---|---|---|---|
| `InspectService` | `GetSummary` | `GetSummaryRequest` | `GetSummaryResponse` (bundle, as_of, history, due items, finding counts, counts, pending plans, setup steps) | no |
| | `ListFindings` | `ListFindingsRequest` (min severity) | `ListFindingsResponse` (`Finding`: reason, severity, subject, evidence, fix command, fix intention, learn path) | no |
| | `ListRoots` | `ListRootsRequest` | `ListRootsResponse` (`Root`: label A or B, keys and card, `OpenPgpCertificate` with primary, user IDs, `SubkeySet` by year and card, `Subkey`; `CloudKey`; `DelegatedKey`) | no |
| | `ListCeremonies` | `ListCeremoniesRequest` | `ListCeremoniesResponse` (`HistoryStatus` and `Ceremony`, newest first, each with the `run_place` where it ran) | no |
| | `ListCards` | `ListCardsRequest` | `ListCardsResponse` (`Card`: `PivApplication` in six `PivRow`s of four `Slot`s, `OpenPgpApplication`, `Fido2Application`) | no |
| | `ListTrustFiles` | `ListTrustFilesRequest` | `ListTrustFilesResponse` (`TrustFile` with its check) | no |
| `PlanService` | `ListIntentions` | `ListIntentionsRequest` | `ListIntentionsResponse` (`IntentionOption`: applicable or greyed with a reason, recommended) | no |
| | `StartPlan` | `StartPlanRequest` (intention, due ids, finding ids, target, `Answer`s) | `StartPlanResponse` (`Question`s, or the `Plan` with its `run_place`, `signing_store`, `signature_count`, `touch_count` and `test_root`, or a refusal) | no (builds in memory) |
| | `SavePlan` | `SavePlanRequest` (plan id, digest) | `SavePlanResponse` (bundle path, path inside the bundle, digest, `written`, notice, run command, what to copy and bring, file preview) | **yes**, one inert file; the demo writes nothing |

Enums, all with an `_UNSPECIFIED = 0` first value and the enum name as prefix:
`Severity`, `Store`, `RunPlace`, `SubjectKind`, `Intention`, `ChainState` (common);
`DueKind`, `RootKind`, `RootState`, `RootKeyKind`, `DelegatedKeyKind`,
`DelegatedKeyState`, `SubkeyUsage`, `SubkeyState`, `RevocationReason`,
`SubkeyOrigin`, `CeremonyKind`, `CeremonyOutcome`, `CardKind`, `CardState`,
`ApplicationUse`, `SlotState`, `SlotUse`, `PinRule`, `TouchRule`,
`TrustFileKind`, `TrustCheckResult` (inspect); `QuestionKind`, `Requirement`,
`BundleChangeAction` (plan).

## Which calls feed which screen

| Screen | Calls |
|---|---|
| **Start** (getting started, what is due) | `GetSummary` (due items, finding counts, history banner, setup steps, pending plans). `ListIntentions` for the "Make a plan" button. |
| **Findings** | `ListFindings`. Each finding's `fix_intention` opens the wizard through `StartPlan`; its `fix_command` and `learn_path` are shown as given. |
| **Key view** (a certificate by year and by card; a root and its delegated keys) | `ListRoots`. Card names come from `ListCards` (join on serial); findings about a key come from `ListFindings` (join on `subject.identifier`). |
| **History** (one record per ceremony) | `ListCeremonies` (the banner is its `history`). |
| **Cards** (inventory and the use of every slot) | `ListCards`. |
| **Trust files** | `ListTrustFiles`. |
| **Wizard: goals** | `ListIntentions`. |
| **Wizard: questions and preview** | `StartPlan` twice: first without answers (questions), then with them (the plan: steps, bundle changes, digest, equivalent command, run command). |
| **Wizard: save and hand-over** | `SavePlan` (path inside the bundle, digest, what to copy and bring, what the plan file holds). In the demo `written` is false and `notice` says so, and the path is `history/<ceremony>/plan.json` (record 0006, rule 7). |

## Things a designer must know

1. **Text is data.** Every string in a response is written by the bundle, not
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
   jobs; `Root.card_row` is 1 to 6 as drawn, so roots start at row 2, and a root
   owns one row on its card. A slot's
   `SlotState` is empty, used, reserved (planned, not born) or spare (a row no root
   owns yet); on a day-to-day card all PIV slots are empty, not spare. A row that
   belongs to another bundle of the same holder (a shared pair of root cards) is
   declared in the card's file and arrives as used slots with `SLOT_USE_OTHER_BUNDLE`
   and no `public_key_sha256`; an occupied row nobody declared is a used slot with no
   use, and a finding. The value and the finding are proposed (record 0003, issue 11).
6. **Counting days.** Use `as_of` from `GetSummary` as "now". `DueItem.severity`
   is already computed (notice at 60 days, alert at 30, critical at 14).
7. **The command is shown, never run.** `fix_command`, `equivalent_command`
   and `run_command` are exact strings to display and copy. A command that runs a
   plan names the bundle's place with `--dir`, as cli.md has it
   (`ritueel --dir BUNDLE run PLAN --confirm DIGEST`), and the plan is the file
   `SavePlan` writes. Their names follow `docs/reference/cli.md` where a command
   exists there: `due` plans without `--plan-only`, `ca-bundle build` builds the CA
   bundle, `--ca-bundle` names it in the verifiers, and `init` makes the first root of
   an empty bundle. A few (`personal primary extend`, `personal primary add`,
   `personal userid revoke`, `personal subkey revoke`, and the `--key` and
   `--expires-in` flags) are proposals that cli.md does not have, until the command
   set is built; `card adopt` and `card check` are the names cli.md gives, marked
   Proposed there, so the page must show them as given and not parse them.
8. **The wizard has three outcomes.** `StartPlan` returns questions, a plan, or
   a refusal. Questions are choices only; there is no free-text answer, so no
   place a secret could be typed. `ListIntentions` marks goals that do not apply,
   with the reason; show them greyed.
9. **Nothing happens here.** A plan's steps are what `ritueel run` does where the
   plan says. `Plan.run_place` follows record 0005, rules 17 and 18: a key that can be
   copied (a key file) is used only in the offline system (vanilla AirgapOS, started
   from the ceremony USB stick), and a key that cannot be copied (a root on cards, a
   cloud root) may be used on the workstation under four conditions: a touch for every
   signature, the number of signatures stated in the plan, no retry of a failed touch,
   and the result checked against the plan on a second device. The plan carries what the
   page needs to say so: `signing_store` (the page cannot tell a key file from a cloud
   key by the other fields), `signature_count` (the sum of the steps' counts),
   `touch_count` (0 for a cloud key, which has no touch: the typed digest and the role session stand, and its audit trail records every signature, record 0005 rule 18)
   and `test_root`. The stick fields of the answer (what goes on the stick, what to
   bring) are empty on the workstation, and the page then shows no stick step. A
   `Requirement` says that a card, a PIN, a touch or a passkey unlock is needed there;
   the PIN is never in the page.
   `SavePlan`
   in the demo answers `written: false` with a notice and a file preview: show
   the preview as "what saving would write". The real call rebuilds the plan, refuses a
   digest that is not the rebuilt plan's, and writes canonical JSON (RFC 8785); its
   SHA-256 is the digest. The file goes to
   `history/<ceremony>/plan.json` inside the bundle (record 0006, rule 7); the names of
   the other members of that folder are proposed.
10. **`int64` is a string in JSON** (`size_bytes`), and `Timestamp` is an
    RFC 3339 string; the generated types turn them into `bigint` and `Timestamp`.
11. **What each example bundle finds.** `globex` has one finding, a cloud key
    waiting to be adopted (`alias/globex-staging-signing`), so that the wizard goal
    "adopt a key" has something to adopt; `personal` and `acme` have none of that
    kind. An empty bundle in the demo recommends the same goal and answers it with a
    plan of its own, `common/plan.start-plan.adopt-key.json`, whichever bundle is open;
    as the bundle has no root yet, that plan starts with `init`, and the transport puts
    the open bundle's place into its commands. A personal bundle has no root list: its
    one trust file is the person's public certificate (`TRUST_FILE_KIND_OPENPGP_CERTIFICATE`).
    `PendingPlan` (`GetSummaryResponse.pending_plans`) lists plans saved as
    `history/<ceremony>/plan.json` and not yet run; no example bundle has one and no
    screen shows the list yet.
12. **A root is written `bundle/label`.** `Root.label` is `A`, `B` and so on, as in
    the bundle's `root.json`; the bundle is named by its directory, and the name
    comes from `GetSummary.bundle.name`. Inside a bundle a root is `A`; across bundles
    it is written with the bundle's name, `acme/A`.
    In this contract no call names or selects a bundle; which bundle the process
    serves is not decided by the records (record 0010, rules 8 and 9). The demo
    has three example bundles and a switch for them; the switch is in the page, not
    in this API.
13. **The four card kinds** are root, day-to-day, server and rehearsal, and a card
    never changes its kind. A server card (`CARD_KIND_SERVER`) stays plugged into a
    server of a requester system and signs for its services. It is an ordinary card,
    not a hardware security module product; ritueel lists it and only ever reads it, so
    it has no adoption, no sealed file and no layout check. A rehearsal card never holds
    a real key, may be reset, and serves only a test root. A root card holds roots by
    row and may serve up to four bundles of one holder. The demo shows a shared pair
    (the personal example) and no server card.
