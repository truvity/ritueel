import { CeremonyCommand } from '../gen/ritueel/local/v1alpha1/common_pb';

// What a command does, in one sentence each, for the panel of a ceremony.
//
// The sentence for `apply` reads record 0005, rules 7 and 9 to 12: the plan, the
// typed first eight characters of its digest, the attempt (written before the first
// key is born), the root key that signs, and the check by code that did not sign,
// with the ceremony record last. The sentence for `close` reads
// record 0005, rules 10 and 14: `close` prints the journals and asks for the first
// eight characters of the digest of the plan. Record 0010 (rule 4) wants one text
// that the page and the guided mode both read. The guided mode does not exist yet,
// so the text is the page's own; the sentences add no fact to those rules. The
// contract does not carry them.

export interface CommandText {
  title: string;
  text: string;
}

export const COMMAND_TEXT: Partial<Record<CeremonyCommand, CommandText>> = {
  [CeremonyCommand.APPLY]: {
    title: 'What apply does',
    text: 'apply writes a plan of what is not applied yet and asks you to type the first eight characters of its digest. It writes an attempt before the first key is born, lets the root key sign, checks every result with code that did not sign it, and writes the ceremony record last.',
  },
  [CeremonyCommand.CLOSE]: {
    title: 'What close does',
    text: "close prints the journals of the attempt, so that you can see what was born and signed, and asks you to type the first eight characters of the plan's digest.",
  },
};
