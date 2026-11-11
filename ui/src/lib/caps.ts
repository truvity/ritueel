// How long each text from the bundle may be before the page cuts it. The page
// shows the cut with a visible marker (lib/safe.ts), and that guard stays: it
// is for text a program sends that nobody wrote for this page. The example
// texts of the demo (src/fixtures) are written to fit these limits, and
// demo.test.ts fails when one does not. Each screen takes its limit from here,
// so the screen and the test cannot disagree.
//
// A key is "<Message>.<field>" of the contract. When one field is drawn in two
// places with two limits, the second key adds "#<place>"; the example text must
// fit the smaller one. A field with no key is drawn with DEFAULT_CAP.
export const CAPS = {
  // The bundle and the summary.
  'Bundle.name': 40,
  'Bundle.path': 60,
  'Bundle.path#shell': 40,
  'GetSummaryResponse.program_version': 30,
  'HistoryStatus.message': 200,
  'HistoryStatus.message#history': 240,
  'DueItem.title': 120,
  'DueItem.title#next': 90,
  'DueItem.detail': 260,
  'SetupStep.title': 100,
  'SetupStep.detail': 220,
  // Findings.
  'Finding.title': 160,
  'Finding.reason': 400,
  'Finding.evidence': 300,
  'Subject.label': 60,
  // Goals and questions.
  'IntentionOption.title': 80,
  'IntentionOption.sentence': 240,
  'IntentionOption.typical_time': 40,
  'IntentionOption.recommended_reason': 200,
  'IntentionOption.not_applicable_reason': 240,
  'Question.prompt': 160,
  'Question.help': 300,
  'QuestionOption.label': 160,
  'QuestionOption.description': 200,
  // The plan and its saving.
  'Plan.title': 100,
  'Plan.summary': 400,
  'Plan.save_path': 120,
  'Plan.card_serials': 20,
  'PlanStep.title': 100,
  'PlanStep.detail': 400,
  'PlanStep.what_changes': 120,
  'PlanStep.card_serials': 20,
  'BundleChange.path': 120,
  'BundleChange.description': 240,
  'SavePlanResponse.notice': 300,
  'SavePlanResponse.bundle_path': 120,
  'SavePlanResponse.path': 120,
  'SavePlanResponse.plan_file_preview': 200, // for each line
  'SavePlanResponse.copy_to_stick': 260,
  'SavePlanResponse.bring': 260,
  'SavePlanResponse.when_back': 300,
  'StartPlanResponse.refusal': 300,
  // Cards.
  'Card.serial': 20,
  'Card.name': 60,
  'Card.name#key': 30,
  'Card.model': 30,
  'Card.firmware': 12,
  'Card.role_summary': 300,
  'Card.kept': 60,
  'Card.kept#compact': 50,
  'Card.changes_since_last_reading': 260,
  'Slot.id': 12,
  'Slot.purpose': 200,
  'Slot.algorithm': 30,
  'PivRow.label': 20,
  // History.
  'Ceremony.title': 120,
  'Ceremony.title#neighbour': 100,
  'Ceremony.summary': 420,
  'Ceremony.summary#open': 500,
  'Ceremony.id': 80,
  'Ceremony.card_serials': 20,
  'Ceremony.subject_labels': 40,
  // Roots and keys.
  'Root.name': 80,
  'Root.note': 400,
  'Root.card_serials': 20,
  'RootKey.algorithm': 20,
  'RootKey.card_serial': 20,
  'RootKey.slot': 12,
  'SubkeySet.card_serial': 20,
  'Subkey.algorithm': 20,
  'UserId.text': 160,
  'CloudKey.alias': 120,
  'CloudKey.alias#facts': 200,
  'CloudKey.provider': 30,
  'CloudKey.provider#facts': 200,
  'CloudKey.region': 30,
  'CloudKey.region#facts': 200,
  'CloudKey.replica_region': 30,
  'CloudKey.replica_region#facts': 200,
  'CloudKey.key_ref': 200,
  'CloudKey.replica_ref': 200,
  'CloudKey.policy_notes': 260,
  'DelegatedKey.name': 60,
  'DelegatedKey.detail': 260,
  'DelegatedKey.requester': 60,
  // Trust files.
  'TrustFile.name': 80,
  'TrustFile.path': 80,
  'TrustFile.check_detail': 300,
} as const;

export type CapKey = keyof typeof CAPS;
