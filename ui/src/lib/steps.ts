import { CeremonyKind } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';

// The usual steps of each kind of ceremony, in the words of the plan steps.
// The contract's Ceremony message carries the digest of the plan it ran but
// not its steps; the demo has no plan files, so the page shows the usual steps
// by kind and says so (the real program would read them from plan.json in the
// history).

export interface UsualStep {
  title: string;
  detail: string;
}

const CHECK: UsualStep = { title: 'Check the plan', detail: 'ritueel compares the plan with the bundle and the history, and you confirm its digest at the terminal.' };
const CARDS: UsualStep = { title: 'Read the cards', detail: 'Every slot of each card in the plan is read and compared with the layout. Nothing is written to a card in this step.' };
const TRUST: UsualStep = { title: 'Build the trust files', detail: 'The root list, the CA bundle, a revocation list for each root, the SSH CA key list and the public OpenPGP keyring are built as the next trust sequence.' };
const RECORD: UsualStep = { title: 'Write the record', detail: 'The record of this ceremony is written. It names the record before it, so the history stays a chain. It says where the ceremony ran.' };

export const USUAL_STEPS: Partial<Record<CeremonyKind, UsualStep[]>> = {
  [CeremonyKind.INIT]: [
    CHECK,
    CARDS,
    { title: 'Make the root keys on each card', detail: 'The X.509 root, the OpenPGP primary and the SSH CA are born in their own row of each root card.' },
    { title: 'Certify the public keys', detail: 'The public halves are written to the bundle with their creation time fixed.' },
    TRUST,
    RECORD,
  ],
  [CeremonyKind.ADOPT_KEY]: [
    CHECK,
    { title: 'Read the public key', detail: 'ritueel reads the public key of the key being adopted and checks it and its policy against its rules. The key is not changed.' },
    { title: 'Write the certificate', detail: 'The certificate is written, with its creation time fixed and recorded.' },
    RECORD,
  ],
  [CeremonyKind.ADD_DELEGATED_KEY]: [
    CHECK,
    CARDS,
    { title: 'Certify the delegated key', detail: 'A root certifies the key of the requester, with limits on what it may do and for how long.' },
    TRUST,
    RECORD,
  ],
  [CeremonyKind.RENEW]: [CHECK, CARDS, { title: 'Sign the renewal', detail: 'A root signs a new certificate or binding for the delegated key. The old one stays valid until it ends.' }, TRUST, RECORD],
  [CeremonyKind.REPLACE]: [CHECK, CARDS, { title: 'Make the new key', detail: 'The new key is made, and the old one is marked as replaced.' }, TRUST, RECORD],
  [CeremonyKind.REVOKE]: [CHECK, CARDS, { title: 'Revoke', detail: 'The revocation is signed with its reason and written to the bundle.' }, TRUST, RECORD],
  [CeremonyKind.CARD_CHECK]: [
    CHECK,
    CARDS,
    { title: 'Prove each card is alive', detail: 'Each card passes the proof of life. Nothing changes outside the record.' },
    RECORD,
  ],
  [CeremonyKind.RESTORE_DRILL]: [
    { title: 'Clone the bundle on a clean machine', detail: 'The check runs on a copy of the bundle, so nothing in your own bundle is touched.' },
    { title: 'Verify the records, the last digest and the signed commits', detail: 'Every record is checked against the one before it, the newest digest against the one you kept apart, and the commits against their signatures.' },
    { title: 'Compare the roots with their holders and check the revocation signatures', detail: 'Each root is compared with the keys its holder has, and every revocation is checked for a valid signature.' },
    { title: 'Write the report', detail: 'The report is written for you to read. No record is written to the history.' },
  ],
};
