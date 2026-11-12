import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import { setScene, useBundle, useScene, useViewState } from '../api/demoState';
import { SCENE_COUNT, sceneLine } from '../api/scenes';
import { T } from './T';

// The same sizes as the other two groups of the demo bar: 44 px on a phone.
const GROUP_SX = { '& .MuiToggleButton-root': { minHeight: { xs: 44, lg: 32 }, fontSize: '0.8125rem', paddingInline: '0.55rem' } } as const;

const NUMBERS = Array.from({ length: SCENE_COUNT }, (_, i) => i + 1);

/**
 * Demo only. Steps through the five scenes of the bundle acme. A scene is one
 * moment of one change: what was done outside the page, and what the page
 * shows after that. The control is drawn for acme and for a loaded bundle
 * only: a scene needs a bundle that answers, and the other two bundles have
 * none. Under the buttons a line says what was done outside the page, in the
 * words "Scene N of 5: ...". It is a status, so a screen reader reads it when
 * the scene changes.
 *
 * It returns two elements for the flex row of the demo bar: the control, and
 * the line on a row of its own under all the controls (order-last).
 */
export function SceneSwitch() {
  const bundle = useBundle();
  const view = useViewState();
  const scene = useScene();
  if (bundle !== 'acme' || view !== 'loaded') return null;
  return (
    <>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span id="scene-switch-label" className="text-sm font-semibold">
          Scene
        </span>
        <ToggleButtonGroup exclusive size="small" value={scene} onChange={(_e, value) => value && setScene(value)} aria-labelledby="scene-switch-label" sx={GROUP_SX}>
          {NUMBERS.map((n) => (
            <ToggleButton key={n} value={n} aria-label={`Scene ${n} of ${SCENE_COUNT}`}>
              {n}
            </ToggleButton>
          ))}
        </ToggleButtonGroup>
      </div>
      <p role="status" aria-live="polite" data-testid="scene-line" className="order-last m-0 w-full max-w-[70ch] text-sm text-dim">
        <T>{`Scene ${scene} of ${SCENE_COUNT}: ${sceneLine(scene)}`}</T>
      </p>
    </>
  );
}
