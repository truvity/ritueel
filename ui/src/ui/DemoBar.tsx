import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import { DEMO_BUNDLES, VIEW_STATES, setBundle, setViewState, useBundle, useViewState } from '../api/demoState';
import { siteUrl } from '../lib/route';
import { SceneSwitch } from './SceneSwitch';

/**
 * The line under the sentence of the bar. It says that the pictures on the site
 * still show the older page. The site step removes it by deleting this constant.
 */
export const SITE_PICTURES_NOTE = 'The pictures on the site still show the older page. They follow in a later step.';

const GROUP_SX = { '& .MuiToggleButton-root': { minHeight: { xs: 44, lg: 32 }, fontSize: '0.8125rem', paddingInline: '0.55rem' } } as const;

/** Demo only. Shows the bundle the demo answers for. The contract has no call that names or selects a bundle, so the real page has no such switch. */
function BundleSwitch() {
  const bundle = useBundle();
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <span id="bundle-switch-label" className="text-sm font-semibold">
        Example bundle
      </span>
      <ToggleButtonGroup exclusive size="small" value={bundle} onChange={(_e, value) => value && setBundle(value)} aria-labelledby="bundle-switch-label" sx={GROUP_SX}>
        {DEMO_BUNDLES.map((b) => (
          <ToggleButton key={b.value} value={b.value} title={b.hint}>
            {b.label}
          </ToggleButton>
        ))}
      </ToggleButtonGroup>
    </div>
  );
}

/** Demo only. Lets a visitor see the four states of every screen. */
function StateSwitch() {
  const view = useViewState();
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <span id="state-switch-label" className="text-sm font-semibold">
        Page state
      </span>
      <ToggleButtonGroup exclusive size="small" value={view} onChange={(_e, value) => value && setViewState(value)} aria-labelledby="state-switch-label" sx={GROUP_SX}>
        {VIEW_STATES.map((s) => (
          <ToggleButton key={s.value} value={s.value} title={s.hint}>
            {s.label}
          </ToggleButton>
        ))}
      </ToggleButtonGroup>
    </div>
  );
}

/**
 * The calm mark that this is a demo: on every screen, in words, with the way
 * back to the site. It only exists in the demo build.
 *
 * Three controls: the example bundle, the scene (acme only, ui/SceneSwitch.tsx)
 * and the page state. From 1024 px the
 * sentence is the first line, and the site line and the controls share the
 * second one. On a phone the order is the sentence, the controls, the site line.
 */
export function DemoBar() {
  return (
    <div role="region" aria-label="This is a demo" data-print="hide" className="z-40 border-b border-rule bg-sunk lg:sticky lg:top-0">
      <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-1 px-4 py-1">
        <p className="order-1 flex w-full min-w-0 flex-wrap items-center gap-x-3 gap-y-0 text-sm">
          <span className="border border-rule bg-panel px-1.5 font-mono text-xs font-bold tracking-wider">DEMO</span>
          <span>The data is made up, and ritueel is still in design. Nothing here acts.</span>
          {/* Below lg the way back is the DEMO mark in the header under this bar and the link in the footer. */}
          <a className="hidden items-center font-semibold text-accent underline underline-offset-4 lg:inline-flex" href={siteUrl()}>
            Back to ritueel.id
          </a>
        </p>
        <div className="order-2 flex flex-wrap items-center gap-x-5 gap-y-1 lg:order-3">
          <BundleSwitch />
          <SceneSwitch />
          <StateSwitch />
        </div>
        <p className="order-3 min-w-0 flex-1 basis-60 text-sm text-dim lg:order-2">{SITE_PICTURES_NOTE}</p>
      </div>
    </div>
  );
}
