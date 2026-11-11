import assert from 'node:assert/strict';
import { test } from 'node:test';
import { githubHeadingIds } from '../lib/headings.mjs';

test('headings: the ids GitHub gives', () => {
  const ids = githubHeadingIds(
    [
      '---',
      'title: Front matter is skipped',
      '# not a heading',
      '---',
      '# Title',
      '## Every six months',
      '## `result.json`',
      '## Why: a colon',
      '### 3. If it is a cloud key: does the key already exist?',
      '## Same',
      '## Same',
      '## A [link](/x/) and *stress*',
      '```',
      '## in a fence',
      '```',
    ].join('\n'),
  );
  assert.deepEqual(
    [...ids],
    [
      'title',
      'every-six-months',
      'resultjson',
      'why-a-colon',
      '3-if-it-is-a-cloud-key-does-the-key-already-exist',
      'same',
      'same-1',
      'a-link-and-stress',
    ],
  );
});
