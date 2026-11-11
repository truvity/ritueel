import { Intention, SubjectKind, type Subject } from '../gen/ritueel/local/v1alpha1/common_pb';
import { href, siteUrl } from './route';

export const INTENTION_SLUG: Partial<Record<Intention, string>> = {
  [Intention.RENEW_DUE]: 'renew-due',
  [Intention.ADOPT_KEY]: 'adopt-key',
  [Intention.REPLACE_SUBKEYS]: 'replace-subkeys',
  [Intention.ADD_CARD]: 'add-card',
  [Intention.REPLACE_CARD]: 'replace-card',
};

export function intentionFromSlug(slug: string | undefined): Intention | undefined {
  const hit = Object.entries(INTENTION_SLUG).find(([, s]) => s === slug);
  return hit ? (Number(hit[0]) as Intention) : undefined;
}

export function planHref(i: Intention): string {
  return href.plan(INTENTION_SLUG[i]);
}

/** Where a subject can be looked at on the page, if anywhere. */
export function subjectHref(s: Subject | undefined, personalLabel = 'personal'): { href: string; label: string } | undefined {
  switch (s?.kind) {
    case SubjectKind.ROOT:
    case SubjectKind.SUBKEY:
    case SubjectKind.USER_ID:
      return { href: href.key(personalLabel), label: 'Open the key' };
    case SubjectKind.DELEGATED_KEY:
      return { href: href.key('acme'), label: 'Open the key' };
    case SubjectKind.CARD:
      return { href: href.cards(s.identifier), label: 'Open the card' };
    case SubjectKind.TRUST_FILE:
      return { href: href.trust(), label: 'Open the trust files' };
    default:
      return undefined;
  }
}

/** A guide on the site. The program gives a path such as /learn/expiry/; the link goes to the site. */
export function learnUrl(path: string): string {
  return siteUrl(learnPathOk(path) ? path : '');
}

/** A guide path the page will link to: a site path of plain letters, digits and "/-_.#" only. */
export function learnPathOk(path: string | undefined): path is string {
  return !!path && /^\/[A-Za-z0-9/_.#-]{0,120}$/.test(path) && !path.includes('..') && !path.startsWith('//');
}
