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
  'GetSummaryResponse.apply_command': 200, // a command; the cap of the Copy control (500) still holds
  'HistoryStatus.message': 200,
  'HistoryStatus.message#history': 240,
  // A reference to an object.
  'ObjectRef.id': 80, // the id in an address and in an element id
  'ObjectRef.label': 60,
  'CeremonyRef.id': 80,
  // Findings.
  'Finding.code': 30,
  'Finding.title': 160,
  'Finding.title#fix': 80, // the label of the fix command
  'Finding.reason': 400,
  'Finding.evidence': 300,
  'Finding.fix_command': 300,
  // Cards.
  'Card.serial': 20,
  'Card.name': 60,
  'Card.name#key': 30,
  'Card.model': 30,
  'Card.firmware': 12,
  'Card.holder': 60, // the card panel
  'Card.role_summary': 300,
  'Card.kept': 60,
  'Card.kept#compact': 50,
  'Card.changes_since_last_reading': 260,
  'Card.revoke_command': 300,
  'Slot.id': 12,
  'Slot.purpose': 200,
  'Slot.algorithm': 30,
  'PivRow.label': 20,
  // Keys, roots, user IDs, delegations, requests.
  'Key.algorithm': 20, // the key panel
  'Key.label': 4, // the key cell
  'Key.root': 80, // the key cell
  'Key.delegation': 60, // the key cell
  'Key.revoke_command': 300,
  'Place.card': 60, // the place cell
  'Place.slot': 12, // the place cell
  'Place.key_ref': 200, // the key panel
  'Place.account': 20, // the group title of the By card view, the place cell of By root and the key panel (an AWS account id has 12 digits)
  'Place.region': 30, // the key panel and the place cell of By card
  'Place.replica_region': 30, // the key panel
  'Place.replica_ref': 200, // the key panel
  'Place.path': 120, // the key panel
  'Root.name': 80,
  'Root.note': 400,
  'Root.wanted_path': 80,
  'UserId.text': 160,
  'UserId.text#cell': 60, // a table cell
  'Delegation.name': 60,
  'Delegation.requester': 60,
  'Delegation.use': 30,
  'Delegation.limits': 120, // each line
  'Delegation.wanted_path': 80,
  'Request.stem': 60,
  'Request.code': 30,
  'Request.path': 80,
  'Request.answer_path': 120,
  // Changes not applied yet.
  'Change.text': 120, // the panel and the Apply block
  'Change.text#cell': 90, // a table cell
  'Change.reason': 160,
  'Change.wanted_path': 80,
  'Need.name': 60,
  // History.
  'Ceremony.id': 80,
  'Ceremony.title': 120,
  'Ceremony.title#cell': 80, // a table cell of History
  'Ceremony.summary': 420,
  'Ceremony.summary#open': 500,
  'Ceremony.cards': 60, // each name
  'Ceremony.trust_set_name': 40,
  'Ceremony.close_reason': 200,
  'Ceremony.guide_path': 80,
  'Ceremony.publish_command': 300,
  'Ceremony.close_command': 300,
  'CeremonyChange.text': 160,
  'CeremonyChange.reason': 240,
  // Trust files.
  'ListTrustFilesResponse.set_name': 40,
  'TrustFile.name': 80,
  'TrustFile.name#cmd': 60, // the label of a command
  'TrustFile.path': 80,
  'TrustFile.check_detail': 300,
  'TrustFile.verify_command': 300,
} as const;

export type CapKey = keyof typeof CAPS;
