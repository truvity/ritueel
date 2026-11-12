import { describe, expect, it } from 'vitest';
import { agoDays, daysBetween, inDays, plural } from './lib/format';
import { endsIn } from './lib/inventory';
import { WORLDS } from './testkit';

// A count of days is written as a person says it: "today", "1 day", "2 days". Never "0 days" or "1 days".

describe('a count of days reads as a person says it', () => {
  it('in N days', () => {
    expect([0, 1, 2, 60].map(inDays)).toEqual(['today', 'in 1 day', 'in 2 days', 'in 60 days']);
    expect([-1, -3].map(inDays)).toEqual(['1 day overdue', '3 days overdue']);
    expect(inDays(undefined)).toBe('-');
  });
  it('N days ago', () => {
    expect([0, 1, 2, 349].map(agoDays)).toEqual(['today', '1 day ago', '2 days ago', '349 days ago']);
  });
  it('the days of a table cell', () => {
    expect([0, 1, 2, 60].map(endsIn)).toEqual(['today', '1 day', '2 days', '60 days']);
    expect([-1, -3].map(endsIn)).toEqual(['ended 1 day ago', 'ended 3 days ago']);
  });
  it('a count with its noun', () => {
    expect([0, 1, 2].map((n) => plural(n, 'day'))).toEqual(['0 days', '1 day', '2 days']);
  });
});

// The message of the history is a sentence of the service. The demo's fixtures hold it, so the
// fixtures must write the age of the newest record the same way.
describe('the history message says how old the newest record is', () => {
  const sentence = (n: number | undefined) => (n === 0 ? 'The newest is from today.' : n === 1 ? 'The newest is 1 day old.' : `The newest is ${n} days old.`);

  it('writes "from today", "1 day old" or "N days old"', () => {
    expect([0, 1, 2, 349].map(sentence)).toEqual(['The newest is from today.', 'The newest is 1 day old.', 'The newest is 2 days old.', 'The newest is 349 days old.']);
  });
  it('in every world, the sentence agrees with the dates of the record and of the check', () => {
    for (const w of WORLDS()) {
      for (const [name, h] of [['summary', w.summary.history], ['ceremonies', w.ceremonies.history]] as const) {
        if (!h || !h.message.includes('The newest is')) continue;
        const n = daysBetween(h.lastRecordAt, h.checkedAt);
        expect(h.message, `${w.id} ${name}`).toContain(sentence(n));
        expect(h.message, `${w.id} ${name}`).not.toMatch(/\b[01] days\b/);
      }
    }
  });
});
