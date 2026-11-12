import { CeremonyCommand } from '../gen/ritueel/local/v1alpha1/common_pb';

// The usual steps of a ceremony, one catalogue for the page.
//
// Record 0005 (rules 3 to 9) gives the six steps of `apply` in this order, and
// rule 7 says what `close` does. Record 0010 (rule 4) wants one catalogue that
// the page and the guided mode both read. The guided mode does not exist yet,
// so the catalogue is the page's own; the sentences below are short readings of
// those rules and add no fact. The contract does not carry the steps of one
// ceremony, so the page shows the usual steps of its command.

export interface UsualStep {
  title: string;
  detail: string;
}

export const USUAL_STEPS: Partial<Record<CeremonyCommand, UsualStep[]>> = {
  [CeremonyCommand.APPLY]: [
    { title: 'Plan', detail: 'ritueel finds what is not applied yet and writes a plan. The plan needs no card.' },
    { title: 'Confirm', detail: 'ritueel shows the plan in words with its digest. You type the first eight characters in the terminal.' },
    { title: 'Reserve', detail: 'Before the first key is born, ritueel writes an attempt and starts its journals.' },
    { title: 'Sign', detail: 'The root key signs. Each fingerprint is shown before its touch.' },
    { title: 'Verify', detail: 'Code that did not sign checks every artifact against its request and the plan.' },
    { title: 'Record', detail: 'ritueel writes the transcript, the artifacts and, last, the ceremony record.' },
  ],
  [CeremonyCommand.CLOSE]: [
    { title: 'Print the journals', detail: 'ritueel prints the journals of the attempt, so that you can see what was born and signed.' },
    { title: 'Write the closing record', detail: 'ritueel writes a closing record. It names the attempt it closes and the reason you gave.' },
  ],
};
