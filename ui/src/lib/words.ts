// The words of the page. The eleven fixed words are: root, delegated key,
// holder, requester, store, ceremony, ledger, record, renew, replace, trust files.
import { Store } from '../gen/ritueel/local/v1alpha1/common_pb';
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
import { FolderChangeAction, Requirement } from '../gen/ritueel/local/v1alpha1/plan_service_pb';

export const STORE_WORD: Record<number, string> = {
  [Store.SOFTWARE_FILE]: 'Encrypted file',
  [Store.ROOT_CARDS]: 'Pair of root cards',
  [Store.CLOUD_KMS]: 'Cloud KMS key',
};

export const STORE_SENTENCE: Record<number, string> = {
  [Store.SOFTWARE_FILE]: 'The key is an encrypted file in a key folder outside your ritueel folder. A passkey on each root card opens it, and a recovery key is kept apart.',
  [Store.ROOT_CARDS]: 'Each root card holds its own key, born on that card, and the keys never leave the cards. You use them only at the ceremony machine, with the card present.',
  [Store.CLOUD_KMS]: 'The key lives in a cloud key service and never leaves it. If ritueel adopted it, it read the public key and the policy and did not change the key.',
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
  [CardKind.DAILY]: 'Day-to-day',
  [CardKind.REHEARSAL]: 'Rehearsal',
  [CardKind.BOARD]: 'Board',
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

export const FOLDER_ACTION_WORD: Record<number, string> = {
  [FolderChangeAction.CREATE]: 'create',
  [FolderChangeAction.REPLACE]: 'replace',
};
