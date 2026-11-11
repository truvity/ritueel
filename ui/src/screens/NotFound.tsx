import { href } from '../lib/route';
import { Page } from '../ui/Page';
import { Empty } from '../ui/Sec';
import { T } from '../ui/T';

/** A hash that names no screen. It says so; it is never shown as another screen. */
export function NotFound({ hash }: { hash: string }) {
  return (
    <Page kicker="Not found" title="There is no such screen">
      <Empty title="This address does not lead anywhere.">
        <p>
          The address <code className="font-mono">
            <T cap={80}>{hash}</T>
          </code>{' '}
          is not one of the screens of this page.
        </p>
        <p>
          <a className="font-semibold text-accent underline underline-offset-4" href={href.start()}>
            Go to Start
          </a>
        </p>
      </Empty>
    </Page>
  );
}
