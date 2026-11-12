// The words of the page. The fixed words are: bundle, root, delegated key,
// delegation, holder, requester, store, ceremony, history, record, renew,
// replace, trust set, wanted, not applied yet, apply. One item of "not applied
// yet" is a change, never a row. A row is one row of four slots on a card.
// Replace means making a new key. A key retires at its wanted date; revoke is
// the separate act of `revoke` (record 0007, rules 3, 4 and 8). The bare word bundle means the directory of one trust
// domain; the trust file keeps its full name, CA bundle.
//
// Every value of an enum of the contract has a word here. A value with no word
// is not drawn. A word that no record or reference page decides is listed as
// proposed in the comments of the contract (proto/), not here.
import {
  CeremonyCommand,
  ChainState,
  ObjectKind,
  RunPlace,
  Severity,
  Store,
} from '../gen/ritueel/local/v1alpha1/common_pb';
import {
  BundleKind,
  CardKind,
  CeremonyOutcome,
  CeremonyState,
  CertificationKind,
  ChangeKind,
  ChangeSource,
  ChangeState,
  DelegationType,
  KeyKind,
  KeyState,
  NeedKind,
  PinRule,
  RequestOutcome,
  SlotState,
  SlotUse,
  TouchRule,
  TrustCheckResult,
  TrustFileKind,
} from '../gen/ritueel/local/v1alpha1/inspect_service_pb';

export const SEVERITY_WORD: Record<number, string> = {
  [Severity.NOTICE]: 'notice',
  [Severity.ALERT]: 'alert',
  [Severity.CRITICAL]: 'critical',
};

export const STORE_WORD: Record<number, string> = {
  [Store.PIV]: 'PIV card',
  [Store.OPENPGP_CARD]: 'OpenPGP card',
  [Store.AWS_KMS]: 'AWS KMS',
  [Store.SOFTWARE]: 'key file',
};

/** Where a ceremony runs, or ran (record 0005, rules 17 to 21), as a phrase: "on this workstation". */
export const RUN_PLACE_WORD: Record<number, string> = {
  [RunPlace.OFFLINE_SYSTEM]: 'in the offline system',
  [RunPlace.WORKSTATION]: 'on this workstation',
};

/** The same as the value of a detail list: "In the offline system", "On this workstation". */
export const RUN_PLACE_VALUE: Record<number, string> = {
  [RunPlace.OFFLINE_SYSTEM]: 'In the offline system',
  [RunPlace.WORKSTATION]: 'On this workstation',
};

export const OBJECT_KIND_WORD: Record<number, string> = {
  [ObjectKind.BUNDLE]: 'bundle',
  [ObjectKind.CARD]: 'card',
  [ObjectKind.ROOT]: 'root',
  [ObjectKind.KEY]: 'key',
  [ObjectKind.USER_ID]: 'user ID',
  [ObjectKind.DELEGATION]: 'delegation',
  [ObjectKind.CERTIFICATION]: 'certification',
  [ObjectKind.REQUEST]: 'request',
  [ObjectKind.CEREMONY]: 'ceremony',
  [ObjectKind.TRUST_SET]: 'trust set',
  [ObjectKind.TRUST_FILE]: 'trust file',
};

/** A root of this kind. */
export const ROOT_KIND_WORD: Record<number, string> = {
  [KeyKind.X509]: 'X.509 root',
  [KeyKind.OPENPGP]: 'OpenPGP root',
  [KeyKind.SSH_CA]: 'SSH CA root',
};

/** A key of a root, by the kind of its root. */
export const ROOT_KEY_WORD: Record<number, string> = {
  [KeyKind.X509]: 'X.509 root key',
  [KeyKind.OPENPGP]: 'OpenPGP primary',
  [KeyKind.SSH_CA]: 'SSH CA key',
};

/** A delegated key, by the kind of its root. */
export const DELEGATED_KEY_WORD: Record<number, string> = {
  [KeyKind.X509]: 'X.509 intermediate key',
  [KeyKind.OPENPGP]: 'OpenPGP subkey',
  [KeyKind.SSH_CA]: 'SSH CA key',
};

export const KEY_STATE_WORD: Record<number, string> = {
  [KeyState.ACTIVE]: 'active',
  [KeyState.RETIRED]: 'retired',
  [KeyState.REVOKED]: 'revoked',
};

export const DELEGATION_TYPE_WORD: Record<number, string> = {
  [DelegationType.X509_INTERMEDIATE]: 'X.509 intermediate',
  [DelegationType.OPENPGP_SUBKEY]: 'OpenPGP subkey',
  [DelegationType.SSH_CA_KEY]: 'SSH CA key',
};

export const CERTIFICATION_KIND_WORD: Record<number, string> = {
  [CertificationKind.ROOT_CERTIFICATE]: 'root certificate',
  [CertificationKind.INTERMEDIATE_CERTIFICATE]: 'intermediate certificate',
  [CertificationKind.SUBKEY_BINDING]: 'subkey binding',
  [CertificationKind.PRIMARY_SELF_SIGNATURE]: 'user ID certification',
};

export const REQUEST_OUTCOME_WORD: Record<number, string> = {
  [RequestOutcome.UNSPECIFIED]: 'no answer yet',
  [RequestOutcome.ISSUED]: 'issued',
  [RequestOutcome.REFUSED]: 'refused',
};

export const CHANGE_KIND_WORD: Record<number, string> = {
  [ChangeKind.ADOPT]: 'adopt',
  [ChangeKind.BIRTH]: 'birth',
  [ChangeKind.CERTIFY]: 'certify',
  [ChangeKind.RETIRE]: 'retire',
  [ChangeKind.RENEW]: 'renew',
  [ChangeKind.ISSUE]: 'issue',
};

export const CHANGE_STATE_WORD: Record<number, string> = {
  [ChangeState.READY]: 'Ready',
  [ChangeState.WAITS]: 'Waits',
};

export const CHANGE_SOURCE_WORD: Record<number, string> = {
  [ChangeSource.WANTED_FILE]: 'wanted file',
  [ChangeSource.HISTORY]: 'history',
  [ChangeSource.DATE]: 'date',
  [ChangeSource.REQUEST]: 'request',
};

/** "card root-b", "request for acme-release", "key file A.openpgp.key.age": the word, then the name. */
export const NEED_KIND_WORD: Record<number, string> = {
  [NeedKind.CARD]: 'card',
  [NeedKind.REQUEST]: 'request for',
  [NeedKind.KEY_FILE]: 'key file',
};

export const CEREMONY_COMMAND_WORD: Record<number, string> = {
  [CeremonyCommand.APPLY]: 'apply',
  [CeremonyCommand.CLOSE]: 'close',
};

export const CEREMONY_STATE_WORD: Record<number, string> = {
  [CeremonyState.PLANNED]: 'planned',
  [CeremonyState.STARTED]: 'started',
  [CeremonyState.RECORDED]: 'recorded',
  [CeremonyState.CLOSED]: 'closed',
};

export const CEREMONY_OUTCOME_WORD: Record<number, string> = {
  [CeremonyOutcome.COMPLETED]: 'completed',
  [CeremonyOutcome.DECLINED]: 'declined',
  [CeremonyOutcome.CLOSED]: 'closed',
};

export const CARD_KIND_WORD: Record<number, string> = {
  [CardKind.ROOT]: 'root card',
  [CardKind.DAY_TO_DAY]: 'day-to-day card',
  [CardKind.REHEARSAL]: 'rehearsal card',
  [CardKind.SERVER]: 'server card',
};

export const CHAIN_STATE_WORD: Record<number, string> = {
  [ChainState.NOT_CHECKED]: 'not checked',
  [ChainState.VERIFIED]: 'verified',
  [ChainState.BROKEN]: 'broken',
};

export const BUNDLE_KIND_WORD: Record<number, string> = {
  [BundleKind.COMPANY]: 'company',
  [BundleKind.PERSONAL]: 'personal',
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

export const TRUST_KIND_WORD: Record<number, string> = {
  [TrustFileKind.ROOT_LIST]: 'root list',
  [TrustFileKind.CA_BUNDLE]: 'CA bundle',
  [TrustFileKind.CRL]: 'CRL',
  [TrustFileKind.SSH_CA_KEYS]: 'SSH CA key list',
  [TrustFileKind.KEYRING]: 'keyring',
  [TrustFileKind.OPENPGP_CERTIFICATE]: 'OpenPGP certificate',
};

export const TRUST_CHECK_WORD: Record<number, string> = {
  [TrustCheckResult.PASSED]: 'passed',
  [TrustCheckResult.PASSED_WITH_WARNING]: 'passed, with a warning',
  [TrustCheckResult.FAILED]: 'failed',
  [TrustCheckResult.NOT_RUN]: 'not run',
};
