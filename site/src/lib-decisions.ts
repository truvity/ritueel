import { getCollection, type CollectionEntry } from 'astro:content';

type Decision = CollectionEntry<'decisions'>;

// The file every record is copied from; it is not a decision.
export const TEMPLATE_ID = '0000-template';

// The records, without the template.
export async function listDecisions(): Promise<Decision[]> {
  const entries = await getCollection('decisions');
  return entries.filter((entry) => entry.id !== TEMPLATE_ID).sort((a, b) => a.id.localeCompare(b.id));
}

// The title of an ADR: its first level-one heading, else its file name.
export function decisionTitle(entry: Decision): string {
  const heading = /^#\s+(.+)$/m.exec(entry.body ?? '');
  return heading ? heading[1].trim() : entry.id;
}

export const sourceUrl = (entry: Decision): string =>
  `https://github.com/truvity/ritueel/blob/main/docs/decisions/${entry.id}.md`;

export const editUrl = (entry: Decision): string =>
  `https://github.com/truvity/ritueel/edit/main/docs/decisions/${entry.id}.md`;

// A record keeps its status and date as the `**Status:**` and `**Date:**` lines under its
// heading (docs/decisions/README.md, checked by tools/checks/decisions.mjs).
const field = (body: string, name: string): string | undefined =>
  new RegExp(`^\\*\\*${name}:\\*\\*\\s*(.+?)\\s*$`, 'm').exec(body)?.[1];

export interface DecisionFacts {
  id: string;
  number: string;
  title: string;
  status: string;
  date: string | null;
}

export function decisionFacts(entry: Decision): DecisionFacts {
  const body = entry.body ?? '';
  const date = field(body, 'Date');
  return {
    id: entry.id,
    number: entry.id.slice(0, 4),
    title: decisionTitle(entry).replace(/^\d{4}\s+[—-]\s+/, ''),
    status: field(body, 'Status') ?? 'Unknown',
    date: date && /^\d{4}-\d{2}-\d{2}$/.test(date) ? date : null,
  };
}
