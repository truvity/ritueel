// The ids that GitHub gives the headings of a Markdown file, which are also the ids Starlight
// gives them. A port of headingIds() in ui/src/links.test.ts, for the scripts that check an
// #anchor of a link into a file of the repository.

/** The ids of the headings of `markdown`, as a Set. A repeated heading gets -1, -2, ... */
export function githubHeadingIds(markdown) {
  const ids = new Set();
  const seen = new Map();
  let fence = '';
  let front = false;
  markdown.split('\n').forEach((line, i) => {
    if (i === 0 && line.trim() === '---') front = true;
    else if (front) {
      if (line.trim() === '---') front = false;
      return;
    }
    const f = /^\s{0,3}(```+|~~~+)/.exec(line);
    if (f) {
      if (!fence) fence = f[1][0];
      else if (f[1][0] === fence) fence = '';
      return;
    }
    if (fence) return;
    const m = /^ {0,3}(#{1,6})[ \t]+(\S.*)$/.exec(line.trimEnd());
    if (!m) return;
    let text = dropClosingHashes(m[2])
      .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
      .replace(/`/g, '')
      .replace(/\*/g, '')
      .replace(/(^|\W)_(.+?)_(?=\W|$)/g, '$1$2');
    // Drop inline HTML tags until none is left, so a tag nested in another one cannot survive a single pass.
    for (let prev = ''; prev !== text; ) {
      prev = text;
      text = text.replace(/<[^>]+>/g, '');
    }
    const base = text
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\p{M}_ -]/gu, '')
      .replace(/ /g, '-');
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    ids.add(n === 0 ? base : `${base}-${n}`);
  });
  return ids;
}

/** "Title ##" -> "Title": the closing hashes of a heading, and the spaces before them. */
function dropClosingHashes(text) {
  let end = text.length;
  while (end > 0 && text[end - 1] === '#') end--;
  if (end === text.length || end === 0 || (text[end - 1] !== ' ' && text[end - 1] !== '\t')) return text;
  while (end > 0 && (text[end - 1] === ' ' || text[end - 1] === '\t')) end--;
  return text.slice(0, end);
}
