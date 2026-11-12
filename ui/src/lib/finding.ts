import { siteUrl } from './route';

/** A guide on the site. The program gives a path such as /learn/revoke/; the link goes to the site. */
export function learnUrl(path: string): string {
  return siteUrl(learnPathOk(path) ? path : '');
}

/** A guide path the page will link to: a site path of plain letters, digits and "/-_.#" only. */
export function learnPathOk(path: string | undefined): path is string {
  return !!path && /^\/[A-Za-z0-9/_.#-]{0,120}$/.test(path) && !path.includes('..') && !path.startsWith('//');
}
