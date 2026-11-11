// The words of the page. The fixed words are: bundle, root, delegated key,
// holder, requester, store, ceremony, history, record, renew, replace, trust files.
// Replace means making a new key; retire is revoking a subkey that a newer one
// already replaced. The bare word bundle means the directory of one trust
// domain; the trust file keeps its full name, CA bundle.
import { RunPlace, Store } from '../gen/ritueel/local/v1alpha1/common_pb';
import {
  CardKind,
  CardState,
  CeremonyKind,
  CeremonyOutcome,
  DelegatedKeyKind,
  DelegatedKeyState,
  PinRule,
  RootKeyKind,
  RootState,
  SlotState,
  SlotUse,
  SubkeyOrigin,
  SubkeyUsage,
  TouchRule,
  TrustCheckResult,
  TrustFileKind,
} from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { BundleChangeAction, Requirement } from '../gen/ritueel/local/v1alpha1/plan_service_pb';

export const STORE_WORD: Record<number, string> = {
  [Store.SOFTWARE_FILE]: 'Encrypted file',
  [Store.ROOT_CARDS]: 'Root card',
  [Store.CLOUD_KMS]: 'Cloud KMS key',
};

export const STORE_SENTENCE: Record<number, string> = {
  [Store.SOFTWARE_FILE]: 'The key is an encrypted file kept beside the bundle (on the extra partition of the stick), never inside it. A passkey on any one of your root cards opens it (a passphrase is the other way), and a recovery key is kept apart. It can be copied, so you use it only in the offline system (a test root is the exception).',
  [Store.ROOT_CARDS]: 'The root has its own key, born on one root card and never leaving it. Its partner root is on the other card. It cannot be copied. You may use it on your workstation with a touch for every signature, the count in the plan, no retry and a check on a second device, or in the offline system.',
  [Store.CLOUD_KMS]: 'The key lives in a cloud key service and never leaves it. If ritueel adopted it, it read the public key and the policy and did not change the key. It cannot be copied. You may use it from your workstation in a session of its ceremony role; the count, no retry and the second-device check apply. A cloud key has no touch: the typed digest and the role session stand, and its audit trail records every signature.',
};

export const ROOT_STATE_WORD: Record<number, string> = {
  [RootState.ACTIVE]: 'active',
  [RootState.OVERLAP]: 'overlap',
  [RootState.RETIRED]: 'retired',
  [RootState.REVOKED]: 'revoked',
};

export const ROOT_KEY_WORD: Record<number, string> = {
  [RootKeyKind.X509_ROOT]: 'X.509 root',
  [RootKeyKind.OPENPGP_PRIMARY]: 'OpenPGP primary',
  [RootKeyKind.SSH_CA]: 'SSH CA',
};

export const DELEGATED_WORD: Record<number, string> = {
  [DelegatedKeyKind.X509_INTERMEDIATE]: 'X.509 intermediate',
  [DelegatedKeyKind.OPENPGP_SUBKEY]: 'OpenPGP subkey',
  [DelegatedKeyKind.SSH_CA_KEY]: 'SSH CA key',
};

export const DELEGATED_STATE_WORD: Record<number, string> = {
  [DelegatedKeyState.ACTIVE]: 'active',
  [DelegatedKeyState.EXPIRED]: 'expired',
  [DelegatedKeyState.REVOKED]: 'revoked',
};

export const USAGE_WORD: Record<number, string> = {
  [SubkeyUsage.SIGN]: 'sign',
  [SubkeyUsage.AUTHENTICATE]: 'authenticate',
  [SubkeyUsage.ENCRYPT]: 'encrypt',
};

export const USAGE_LETTER: Record<number, string> = {
  [SubkeyUsage.SIGN]: 'S',
  [SubkeyUsage.AUTHENTICATE]: 'A',
  [SubkeyUsage.ENCRYPT]: 'E',
};

export const ORIGIN_WORD: Record<number, string> = {
  [SubkeyOrigin.BORN_ON_CARD]: 'born on a card',
  [SubkeyOrigin.MADE_IN_SOFTWARE]: 'made in software',
  [SubkeyOrigin.BORN_IN_KMS]: 'born in the cloud KMS',
};

export const CARD_KIND_WORD: Record<number, string> = {
  [CardKind.ROOT]: 'Root card',
  [CardKind.DAY_TO_DAY]: 'Day-to-day card',
  [CardKind.REHEARSAL]: 'Rehearsal card',
  [CardKind.SERVER]: 'Server card',
};

export const CARD_STATE_WORD: Record<number, string> = {
  [CardState.ACTIVE]: 'active',
  [CardState.RETIRED]: 'retired',
  [CardState.LOST]: 'lost',
};

export const SLOT_STATE_WORD: Record<number, string> = {
  [SlotState.EMPTY]: 'empty',
  [SlotState.USED]: 'in use',
  [SlotState.RESERVED]: 'reserved: planned, not born yet',
  [SlotState.SPARE]: 'spare: no root owns this row yet',
};

/** Short tag drawn in a slot (at most eight characters, so it fits a phone). */
export const SLOT_USE_TAG: Record<number, string> = {
  [SlotUse.X509_ROOT]: 'X.509',
  [SlotUse.OPENPGP_PRIMARY]: 'PGP',
  [SlotUse.SSH_CA]: 'SSH',
  [SlotUse.UNLOCK_KEY]: 'UNLOCK',
  [SlotUse.OPENPGP_SIGN]: 'SIGN',
  [SlotUse.OPENPGP_DECRYPT]: 'DECRYPT',
  [SlotUse.OPENPGP_AUTHENTICATE]: 'AUTH',
  [SlotUse.PASSKEY_SIGN_IN]: 'SIGN-IN',
  [SlotUse.PASSKEY_SSH]: 'SSH',
  [SlotUse.PASSKEY_UNLOCK]: 'UNLOCK',
  [SlotUse.REHEARSAL]: 'PRACTICE',
  [SlotUse.OTHER_BUNDLE]: 'OTHER',
};

export const PIN_WORD: Record<number, string> = {
  [PinRule.NEVER]: 'never asked',
  [PinRule.ONCE]: 'asked once, then remembered for a while',
  [PinRule.ALWAYS]: 'asked every time',
};

export const TOUCH_WORD: Record<number, string> = {
  [TouchRule.NEVER]: 'never asked',
  [TouchRule.CACHED]: 'asked once in a while (cached)',
  [TouchRule.ALWAYS]: 'asked every time',
};

export const CEREMONY_KIND_WORD: Record<number, string> = {
  [CeremonyKind.INIT]: 'Start of a root',
  [CeremonyKind.ADOPT_KEY]: 'Adopt a key',
  [CeremonyKind.ADD_DELEGATED_KEY]: 'Add a delegated key',
  [CeremonyKind.RENEW]: 'Renew',
  [CeremonyKind.REPLACE]: 'Replace',
  [CeremonyKind.REVOKE]: 'Revoke',
  [CeremonyKind.CARD_CHECK]: 'Card check',
  [CeremonyKind.RESTORE_DRILL]: 'Restore drill',
};

export const OUTCOME_WORD: Record<number, string> = {
  [CeremonyOutcome.DONE]: 'done',
  [CeremonyOutcome.NOT_CONFIRMED]: 'not confirmed',
  [CeremonyOutcome.REFUSED]: 'refused',
  [CeremonyOutcome.UNRESOLVED]: 'unresolved',
};

export const TRUST_KIND_WORD: Record<number, string> = {
  [TrustFileKind.ROOT_LIST]: 'Root list',
  [TrustFileKind.CA_BUNDLE]: 'CA bundle',
  [TrustFileKind.CRL]: 'Revocation list (CRL)',
  [TrustFileKind.SSH_CA_KEYS]: 'SSH CA keys',
  [TrustFileKind.KEYRING]: 'Keyring',
  [TrustFileKind.OPENPGP_CERTIFICATE]: 'Public certificate',
};

export const TRUST_CHECK_WORD: Record<number, string> = {
  [TrustCheckResult.PASSED]: 'check passed',
  [TrustCheckResult.PASSED_WITH_WARNING]: 'check passed with a warning',
  [TrustCheckResult.FAILED]: 'check failed',
  [TrustCheckResult.NOT_RUN]: 'not built',
};

export const REQUIREMENT_WORD: Record<number, string> = {
  [Requirement.CARD_PRESENT]: 'Card present',
  [Requirement.PIN_AT_TERMINAL]: 'PIN typed at the terminal',
  [Requirement.TOUCH]: 'Touch the card',
  [Requirement.KEY_FILE_UNLOCK]: 'Key file opened by a passkey',
  [Requirement.CONFIRM_DIGEST_AT_TERMINAL]: 'Digest confirmed at the terminal',
};

/**
 * Where a plan is run (record 0005, rules 17 and 18): in the offline system for a key that can be copied (a key file),
 * on your workstation for a key that cannot be copied (a root on cards or in the cloud), under four conditions the plan lists.
 */
export const RUN_PLACE_WORD: Record<number, string> = {
  [RunPlace.OFFLINE_SYSTEM]: 'in the offline system',
  [RunPlace.WORKSTATION]: 'on your workstation',
};

/** What the page says when a plan does not say where it is run. */
export const RUN_PLACE_DEFAULT = 'in the terminal where you run it';

/** "in the offline system", "on your workstation", or "in the terminal where you run it". */
export function onPlace(place: RunPlace | undefined): string {
  return RUN_PLACE_WORD[place ?? RunPlace.UNSPECIFIED] ?? RUN_PLACE_DEFAULT;
}

/** Where a ceremony of the history ran (record 0005, rule 2), in a clause: "ran on the workstation". */
export const RAN_PLACE_WORD: Record<number, string> = {
  [RunPlace.OFFLINE_SYSTEM]: 'ran in the offline system',
  [RunPlace.WORKSTATION]: 'ran on the workstation',
};

/** The same as a value of a detail list: "In the offline system", "On the workstation". */
export const RAN_PLACE_VALUE: Record<number, string> = {
  [RunPlace.OFFLINE_SYSTEM]: 'In the offline system',
  [RunPlace.WORKSTATION]: 'On the workstation',
};

export const BUNDLE_ACTION_WORD: Record<number, string> = {
  [BundleChangeAction.CREATE]: 'create',
  // Not "replace": the site's glossary keeps that word for making a new key. This file is rewritten.
  [BundleChangeAction.REPLACE]: 'rewrite',
};
