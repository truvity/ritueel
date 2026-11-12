import { useId } from 'react';
import Button from '@mui/material/Button';
import { safeString } from '../lib/safe';
import { COPY_BUTTON_SX, useCopy } from './Cmd';

/**
 * A path of a file in the bundle, shown in `code` with a Copy control. The
 * control writes exactly the path and is off when the page would not show the
 * path whole (the same rule as `Cmd`). The path is the description of the
 * control; its name is "Copy the path".
 */
export function PathCopy({ path, cap = 120 }: { path: string; cap?: number }) {
  const id = useId();
  // A path that is cut on screen is not copied: the control writes what the screen shows.
  const { canCopy, done, copy } = useCopy(path.length <= cap ? path : '');
  return (
    <div className="flex max-w-[70ch] min-w-0 items-stretch border border-rule bg-sunk">
      <code id={id} className="min-w-0 flex-1 px-3 py-1.5 font-mono text-[0.8125rem] leading-relaxed [overflow-wrap:anywhere] select-all">
        {safeString(path, cap)}
      </code>
      <Button onClick={copy} disabled={!canCopy} aria-label="Copy the path" aria-describedby={id} sx={COPY_BUTTON_SX} className="border-l border-line">
        {done ? 'Copied' : 'Copy'}
      </Button>
    </div>
  );
}
