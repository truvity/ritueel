/**
 * The mark of a change not applied yet on an object: the count in a bordered
 * box, then text for a screen reader ("2 changes not applied yet"). Nothing is
 * drawn for a count of zero.
 */
export function ChangeMark({ count }: { count: number }) {
  if (count <= 0) return null;
  return (
    <span className="inline-flex items-baseline gap-1">
      <span className="inline-block min-w-5 border border-rule px-1 text-center font-mono text-xs leading-5 font-bold">{count}</span>
      <span className="sr-only">{count === 1 ? 'change not applied yet' : 'changes not applied yet'}</span>
    </span>
  );
}
