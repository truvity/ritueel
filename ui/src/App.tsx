import { useRoute } from './lib/route';
import { Shell } from './ui/Shell';
import { Cards } from './screens/Cards';
import { Findings } from './screens/Findings';
import { History } from './screens/History';
import { Key } from './screens/Key';
import { NotFound } from './screens/NotFound';
import { Plan } from './screens/Plan';
import { Roots } from './screens/Roots';
import { Start } from './screens/Start';
import { Trust } from './screens/Trust';

export function App() {
  const route = useRoute();
  let screen;
  switch (route.name) {
    case 'findings':
      screen = <Findings />;
      break;
    case 'roots':
      screen = <Roots />;
      break;
    case 'key':
      screen = <Key root={route.root} />;
      break;
    case 'cards':
      screen = <Cards serial={route.serial} />;
      break;
    case 'history':
      screen = <History id={route.id} />;
      break;
    case 'trust':
      screen = <Trust />;
      break;
    case 'plan':
      screen = <Plan goal={route.goal} />;
      break;
    case 'notfound':
      screen = <NotFound hash={route.hash} />;
      break;
    default:
      screen = <Start />;
  }
  return <Shell route={route}>{screen}</Shell>;
}
